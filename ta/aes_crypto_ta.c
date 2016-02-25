/**
 * Copyright (C) STM 2016. Linaro LTD
 * Author: Zoltan Kuscsik <zoltan.kuscsik@linaro.org>
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <aes_crypto_ta.h>

#define STR_TRACE_USER_TA "SECAES_DEMO"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define CHECK(res, name, action) do { \
    if ((res) != TEE_SUCCESS) { \
      DMSG(name ": 0x%08x", (res)); \
      action \
    } \
  } while(0)

static TEE_OperationHandle crypto_op = NULL;
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
  return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */

void TA_DestroyEntryPoint(void)
{
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
    TEE_Param  params[4], void **sess_ctx)
{
  uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
               TEE_PARAM_TYPE_NONE,
               TEE_PARAM_TYPE_NONE,
               TEE_PARAM_TYPE_NONE);
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  /* Unused parameters */
  (void)&params;
  (void)&sess_ctx;

  /*
   * The DMSG() macro is non-standard, TEE Internal API doesn't
   * specify any means to logging from a TA.
   */
  DMSG("Session created");
  /* If return value != TEE_SUCCESS the session will not be created. */
  return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
  (void)&sess_ctx; /* Unused parameter */

  if (crypto_op)
    TEE_FreeOperation(crypto_op);
  DMSG("Session closed");
}

/* Decrypt chunk of data */
static TEE_Result decrypt_128_ctr_aes(void *in, size_t sz, /*input buffer and size */
        void *out, size_t *outsz, /*output buffer and size */
        uint8_t* aes_key, size_t aes_key_size, /* AES key */
        uint8_t* iv, uint8_t iv_size /*AES IV */
    )
{
  TEE_Result res;
  TEE_ObjectHandle hkey;
  TEE_Attribute attr;

  if (!crypto_op) {
    res = TEE_AllocateOperation(&crypto_op, TEE_ALG_AES_CTR,
              TEE_MODE_DECRYPT, 128);
    CHECK(res, "TEE_AllocateOperation", return res;);

    res = TEE_AllocateTransientObject(TEE_TYPE_AES, 128, &hkey);
    CHECK(res, "TEE_AllocateTransientObject", return res;);

    attr.attributeID = TEE_ATTR_SECRET_VALUE;
    attr.content.ref.buffer = aes_key;
    attr.content.ref.length = aes_key_size;

    res = TEE_PopulateTransientObject(hkey, &attr, 1);
    CHECK(res, "TEE_PopulateTransientObject", return res;);

    res = TEE_SetOperationKey(crypto_op, hkey);
    CHECK(res, "TEE_SetOperationKey", return res;);

    TEE_FreeTransientObject(hkey);
  }
  TEE_CipherInit(crypto_op, iv, iv_size);
  res = TEE_CipherDoFinal(crypto_op, in, sz, out, outsz);
  CHECK(res, "TEE_CipherDoFinal", return res;);
  if(*outsz != sz) {
    DMSG("FXIME: output buffer size does not match the input buffer size");
    return TEE_ERROR_GENERIC;
  }
  return TEE_SUCCESS;
}

static TEE_Result aes_Ctr128_Encrypt(uint32_t param_types, TEE_Param params[4])
{
  TEE_Result res;
  void *buf, *outbuf, *iv, *key;
  size_t sz, outsz,  iv_size, key_size;

  uint32_t exp_param_types = AES_CTR128_ENCRYPT_TEE_PARAM_TYPES;

  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  /* Input buffer */
  buf = params[PARAM_AES_ENCRYPTED_BUFFER_IDX].memref.buffer;
  sz = params[PARAM_AES_ENCRYPTED_BUFFER_IDX].memref.size;

  outbuf = params[PARAM_AES_DECRYPTED_BUFFER_IDX].memref.buffer;
  outsz = params[PARAM_AES_DECRYPTED_BUFFER_IDX].memref.size;

  /* AES IV */
  iv = params[PARAM_AES_IV_IDX].memref.buffer;
  iv_size = params[PARAM_AES_IV_IDX].memref.size;

  /* AES KEY
   *
   * Here we are passing clearkey only. For non-clear key implementation
   * we have to add a flag on setting the key type and use a key Id instead
   * of passing around the key in open.
   *
   * */
  key = params[PARAM_AES_KEY].memref.buffer;
  key_size = params[PARAM_AES_KEY].memref.size;

  if (key_size == 0)
    return TEE_ERROR_SHORT_BUFFER;

  /*
   * By not setting TEE_MEMORY_ACCESS_ANY_OWNER flag, we check
   * that the output buffer cannot be observed by a less trusted
   * component.
   */
  res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_WRITE,
            outbuf, outsz);

  if (res != TEE_SUCCESS)
    DMSG("%s: WARNING: output buffer is not secure", __func__);


  res = decrypt_128_ctr_aes(buf, sz, outbuf, &outsz,
            (uint8_t*) key, key_size,
            (uint8_t*) iv,  iv_size
           );

  if (res != TEE_SUCCESS)
      return res;

  return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
      uint32_t param_types, TEE_Param params[TEE_NUM_PARAMS])
{
  (void)&sess_ctx; /* Unused parameter */

  switch (cmd_id) {
  case TA_AES_CTR128_ENCRYPT:
    return aes_Ctr128_Encrypt(param_types, params);
  default:
    return TEE_ERROR_BAD_PARAMETERS;
  }
}
