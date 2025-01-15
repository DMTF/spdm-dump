/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

void *m_spdm_dec_message_buffer;
void *m_spdm_context;

void *m_spdm_last_message_buffer;
size_t m_spdm_last_message_buffer_size;
uint8_t m_cached_get_measurement_request_attribute;
uint8_t m_cached_get_measurement_operation;
uint8_t m_cached_measurement_summary_hash_type;
uint32_t m_cached_session_id;
void *m_current_session_info;
uint32_t m_current_session_id;
bool m_encapsulated;
bool m_decrypted;
bool m_chunk_large_message;
/*chunk_send command last chunk flag*/
bool m_chunk_send_lask_chunk_flag;

void *m_spdm_cert_chain_buffer;
size_t m_spdm_cert_chain_buffer_size;
size_t m_cached_spdm_cert_chain_buffer_offset;

void *m_local_used_cert_chain_buffer;
size_t m_local_used_cert_chain_buffer_size;
void *m_peer_cert_chain_buffer;
size_t m_peer_cert_chain_buffer_size;

void *m_spdm_mel_buffer;
size_t m_spdm_mel_buffer_size;
size_t m_cached_spdm_mel_buffer_offset;

uint32_t m_spdm_requester_capabilities_flags;
uint32_t m_spdm_responder_capabilities_flags;
uint8_t m_spdm_measurement_spec;
uint32_t m_spdm_measurement_hash_algo;
uint32_t m_spdm_base_asym_algo;
uint32_t m_spdm_base_hash_algo;
uint32_t m_spdm_pqc_asym_algo;
uint16_t m_spdm_dhe_named_group;
uint16_t m_spdm_aead_cipher_suite;
uint16_t m_spdm_req_base_asym_alg;
uint16_t m_spdm_key_schedule;
uint8_t m_spdm_other_params_support;
uint8_t m_spdm_mel_spec;
uint32_t m_spdm_req_pqc_asym_alg;
uint32_t m_spdm_kem_alg;

bool m_multi_key_conn_req;
bool m_multi_key_conn_rsp;

dispatch_table_entry_t m_spdm_vendor_dispatch[] = {
    { SPDM_REGISTRY_ID_DMTF, "DMTF", NULL },
    { SPDM_REGISTRY_ID_TCG, "TCG", NULL },
    { SPDM_REGISTRY_ID_USB, "USB", NULL },
    { SPDM_REGISTRY_ID_PCISIG, "PCISIG", dump_spdm_vendor_pci },
    { SPDM_REGISTRY_ID_IANA, "IANA", NULL },
    { SPDM_REGISTRY_ID_HDBASET, "HDBASET", NULL },
    { SPDM_REGISTRY_ID_MIPI, "MIPI", NULL },
    { SPDM_REGISTRY_ID_CXL, "CXL", NULL },
    { SPDM_REGISTRY_ID_JEDEC, "JEDEC", NULL },
};

value_string_entry_t m_spdm_requester_capabilities_string_table[] = {
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP, "CERT" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP, "CHAL" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCRYPT_CAP, "ENCRYPT" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MAC_CAP, "MAC" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MUT_AUTH_CAP, "MUT_AUTH" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_EX_CAP, "KEY_EX" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PSK_CAP_REQUESTER, "PSK" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_ENCAP_CAP, "ENCAP" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HBEAT_CAP, "HBEAT" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_KEY_UPD_CAP, "KEY_UPD" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
      "HANDSHAKE_IN_CLEAR" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_PUB_KEY_ID_CAP, "PUB_KEY_ID" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHUNK_CAP, "CHUNK" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_NO_SIG, "EP_INFO_NO_SIG" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EP_INFO_CAP_SIG, "EP_INFO_SIG" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_EVENT_CAP, "EVENT" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_ONLY, "MULTI_KEY_ONLY" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_MULTI_KEY_CAP_NEG, "MULTI_KEY_NEG" },
    { SPDM_GET_CAPABILITIES_REQUEST_FLAGS_LARGE_CERT_CAP, "LARGE_CERT" },
};
size_t m_spdm_requester_capabilities_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_requester_capabilities_string_table);

value_string_entry_t m_spdm_responder_capabilities_string_table[] = {
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CACHE_CAP, "CACHE" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_CAP, "CERT" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHAL_CAP, "CHAL" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_NO_SIG, "MEAS_NO_SIG" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP_SIG, "MEAS_SIG" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_FRESH_CAP, "MEAS_FRESH" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCRYPT_CAP, "ENCRYPT" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MAC_CAP, "MAC" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MUT_AUTH_CAP, "MUT_AUTH" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_EX_CAP, "KEY_EX" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER, "PSK" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT,
      "PSK_WITH_CONTEXT" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ENCAP_CAP, "ENCAP" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HBEAT_CAP, "HBEAT" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_KEY_UPD_CAP, "KEY_UPD" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP,
      "HANDSHAKE_IN_CLEAR" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PUB_KEY_ID_CAP, "PUB_KEY_ID" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CHUNK_CAP, "CHUNK" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_ALIAS_CERT_CAP, "ALIAS_CERT" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_CERT_CAP, "SET_CERT" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CSR_CAP, "CSR" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_CERT_INSTALL_RESET_CAP, "CERT_INSTALL_RESET" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_NO_SIG, "EP_INFO_NO_SIG" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EP_INFO_CAP_SIG, "EP_INFO_SIG" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEL_CAP, "MEL" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_EVENT_CAP, "EVENT" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_ONLY, "MULTI_KEY_ONLY" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MULTI_KEY_CAP_NEG, "MULTI_KEY_NEG" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_GET_KEY_PAIR_INFO_CAP, "GET_KEY_PAIR_INFO" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_INFO_CAP, "SET_KEY_PAIR_INFO" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_SET_KEY_PAIR_RESET_CAP, "SET_KEY_PAIR_RESET" },
    { SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_LARGE_CERT_CAP, "LARGE_CERT" },
};
size_t m_spdm_responder_capabilities_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_responder_capabilities_string_table);

value_string_entry_t m_spdm_hash_value_string_table[] = {
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_256, "SHA_256" },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_384, "SHA_384" },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA_512, "SHA_512" },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256" },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384" },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512" },
    { SPDM_ALGORITHMS_BASE_HASH_ALGO_TPM_ALG_SM3_256, "SM3_256" },
};
size_t m_spdm_hash_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_hash_value_string_table);

value_string_entry_t m_spdm_measurement_hash_value_string_table[] = {
    { SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_RAW_BIT_STREAM_ONLY,
      "RAW_BIT" },
    { SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_256, "SHA_256" },
    { SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_384, "SHA_384" },
    { SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA_512, "SHA_512" },
    { SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_256, "SHA3_256" },
    { SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_384, "SHA3_384" },
    { SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SHA3_512, "SHA3_512" },
    { SPDM_ALGORITHMS_MEASUREMENT_HASH_ALGO_TPM_ALG_SM3_256, "SM3_256" },
};
size_t m_spdm_measurement_hash_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_measurement_hash_value_string_table);

value_string_entry_t m_spdm_asym_value_string_table[] = {
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_2048, "RSASSA_2048" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_3072, "RSASSA_3072" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSASSA_4096, "RSASSA_4096" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_2048, "RSAPSS_2048" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_3072, "RSAPSS_3072" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_RSAPSS_4096, "RSAPSS_4096" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P256,
      "ECDSA_P256" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P384,
      "ECDSA_P384" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_ECDSA_ECC_NIST_P521,
      "ECDSA_P521" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_TPM_ALG_SM2_ECC_SM2_P256, "SM2_P256" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED25519, "EDDSA_25519" },
    { SPDM_ALGORITHMS_BASE_ASYM_ALGO_EDDSA_ED448, "EDDSA_448" },
};
size_t m_spdm_asym_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_asym_value_string_table);

value_string_entry_t m_spdm_dhe_value_string_table[] = {
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_2048, "FFDHE_2048" },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_3072, "FFDHE_3072" },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_FFDHE_4096, "FFDHE_4096" },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_256_R1, "SECP_256_R1" },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_384_R1, "SECP_384_R1" },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_SECP_521_R1, "SECP_521_R1" },
    { SPDM_ALGORITHMS_DHE_NAMED_GROUP_SM2_P256, "SM2_P256" },
};
size_t m_spdm_dhe_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_dhe_value_string_table);

value_string_entry_t m_spdm_aead_value_string_table[] = {
    { SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_128_GCM, "AES_128_GCM" },
    { SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AES_256_GCM, "AES_256_GCM" },
    { SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_CHACHA20_POLY1305,
      "CHACHA20_POLY1305" },
    { SPDM_ALGORITHMS_AEAD_CIPHER_SUITE_AEAD_SM4_GCM, "SM4_128_GCM" },
};
size_t m_spdm_aead_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_aead_value_string_table);

value_string_entry_t m_spdm_key_schedule_value_string_table[] = {
    { SPDM_ALGORITHMS_KEY_SCHEDULE_HMAC_HASH, "HMAC_HASH" },
};
size_t m_spdm_key_schedule_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_key_schedule_value_string_table);

value_string_entry_t m_spdm_measurement_spec_value_string_table[] = {
    { SPDM_MEASUREMENT_SPECIFICATION_DMTF, "DMTF" },
};
size_t m_spdm_measurement_spec_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_measurement_spec_value_string_table);

value_string_entry_t m_spdm_mel_spec_value_string_table[] = {
    { SPDM_MEL_SPECIFICATION_DMTF, "DMTF" },
};
size_t m_spdm_mel_spec_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_mel_spec_value_string_table);

value_string_entry_t m_spdm_other_param_value_string_table[] = {
    { SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0, "OPAQUE_FMT_0" },
    { SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1, "OPAQUE_FMT_1" },
    { SPDM_ALGORITHMS_MULTI_KEY_CONN, "MULTI_KEY_CONN" },
};
size_t m_spdm_other_param_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_other_param_value_string_table);

value_string_entry_t m_spdm_pqc_asym_value_string_table[] = {
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_44, "ML_DSA_44" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_65, "ML_DSA_65" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_ML_DSA_87, "ML_DSA_87" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128S, "SLH_DSA_SHA2_128S" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128S, "SLH_DSA_SHAKE_128S" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_128F, "SLH_DSA_SHA2_128F" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_128F, "SLH_DSA_SHAKE_128F" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192S, "SLH_DSA_SHA2_192S" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192S, "SLH_DSA_SHAKE_192S" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_192F, "SLH_DSA_SHA2_192F" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_192F, "SLH_DSA_SHAKE_192F" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256S, "SLH_DSA_SHA2_256S" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256S, "SLH_DSA_SHAKE_256S" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHA2_256F, "SLH_DSA_SHA2_256F" },
    { SPDM_ALGORITHMS_PQC_ASYM_ALGO_SLH_DSA_SHAKE_256F, "SLH_DSA_SHAKE_256F" },
};
size_t m_spdm_pqc_asym_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_pqc_asym_value_string_table);

value_string_entry_t m_spdm_kem_value_string_table[] = {
    { SPDM_ALGORITHMS_KEM_ALG_ML_KEM_512, "ML_KEM_512" },
    { SPDM_ALGORITHMS_KEM_ALG_ML_KEM_768, "ML_KEM_768" },
    { SPDM_ALGORITHMS_KEM_ALG_ML_KEM_1024, "ML_KEM_1024" },
};
size_t m_spdm_kem_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_kem_value_string_table);

value_string_entry_t m_spdm_cert_model_string_table[] = {
    { SPDM_CERTIFICATE_INFO_CERT_MODEL_NONE, "NONE" },
    { SPDM_CERTIFICATE_INFO_CERT_MODEL_DEVICE_CERT, "DEVICE" },
    { SPDM_CERTIFICATE_INFO_CERT_MODEL_ALIAS_CERT, "ALIAS" },
    { SPDM_CERTIFICATE_INFO_CERT_MODEL_GENERIC_CERT, "GENERIC" },
};

value_string_entry_t m_spdm_key_usage_value_string_table[] = {
    { SPDM_KEY_USAGE_BIT_MASK_KEY_EX_USE, "KEY_EX" },
    { SPDM_KEY_USAGE_BIT_MASK_CHALLENGE_USE, "CHALL" },
    { SPDM_KEY_USAGE_BIT_MASK_MEASUREMENT_USE, "MEAS" },
    { SPDM_KEY_USAGE_BIT_MASK_ENDPOINT_INFO_USE, "EP_INFO" },
    { SPDM_KEY_USAGE_BIT_MASK_STANDARDS_KEY_USE, "STD" },
    { SPDM_KEY_USAGE_BIT_MASK_VENDOR_KEY_USE, "VENDOR" },
};

value_string_entry_t m_spdm_get_cert_attribute_string_table[] = {
    { SPDM_GET_CERTIFICATE_REQUEST_ATTRIBUTES_SLOT_SIZE_REQUESTED, "SLOT_SIZE" },
};

value_string_entry_t m_spdm_measurement_type_value_string_table[] = {
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_IMMUTABLE_ROM,
      "ImmutableROM" },
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MUTABLE_FIRMWARE,
      "MutableFirmware" },
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_HARDWARE_CONFIGURATION,
      "HardwareConfig" },
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_FIRMWARE_CONFIGURATION,
      "FirmwareConfig" },
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MEASUREMENT_MANIFEST,
      "Manifest" },
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_DEVICE_MODE,
      "DeviceMode" },
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_VERSION,
      "Version" },
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER,
      "SVN" },
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_HASH_EXTEND_MEASUREMENT,
      "HEM" },
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_INFORMATIONAL,
      "Info" },
    { SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_STRUCTURED_MEASUREMENT_MANIFEST,
      "StructManifest" },
};

value_string_entry_t m_spdm_measurement_device_operation_mode_value_string_table[] = {
    { SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_MANUFACTURING_MODE,
      "Mfg" },
    { SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_VALIDATION_MODE,
      "Val" },
    { SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_NORMAL_MODE,
      "Nor" },
    { SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_RECOVERY_MODE,
      "Rec" },
    { SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_RMA_MODE,
      "Rma" },
    { SPDM_MEASUREMENT_DEVICE_OPERATION_MODE_DECOMMISSIONED_MODE,
      "Dec" },
};

value_string_entry_t m_spdm_measurement_device_mode_value_string_table[] = {
    { SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_IS_ACTIVE,
      "NonInvAct" },
    { SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_IS_ACTIVE,
      "InvAct" },
    { SPDM_MEASUREMENT_DEVICE_MODE_NON_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE,
      "NonInvBeenAct" },
    { SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE,
      "InvBeenAct" },
    { SPDM_MEASUREMENT_DEVICE_MODE_INVASIVE_DEBUG_MODE_HAS_BEEN_ACTIVE_AFTER_MFG,
      "InvBeenActMfg" },
};

value_string_entry_t m_spdm_request_hash_type_string_table[] = {
    { SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH, "NoHash" },
    { SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH, "TcbHash" },
    { SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH, "AllHash" },
};

value_string_entry_t m_spdm_measurement_attribute_string_table[] = {
    { SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE,
      "GenSig" },
    { SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_RAW_BIT_STREAM_REQUESTED,
      "RawBitReq" },
    { SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_NEW_MEASUREMENT_REQUESTED,
      "NewMeasReq" },
};

value_string_entry_t m_spdm_measurement_content_change_string_table[] = {
    { SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_NO_DETECTION,
      "NoCap" },
    { SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_DETECTED,
      "Changed" },
    { SPDM_MEASUREMENTS_RESPONSE_CONTENT_NO_CHANGE_DETECTED,
      "NoChange" },
};

value_string_entry_t m_spdm_challenge_auth_attribute_string_table[] = {
    { SPDM_CHALLENGE_AUTH_RESPONSE_ATTRIBUTE_BASIC_MUT_AUTH_REQ,
      "BasicMutAuth" },
};

value_string_entry_t m_spdm_key_exchange_session_policy_string_table[] = {
    { SPDM_KEY_EXCHANGE_REQUEST_SESSION_POLICY_TERMINATION_POLICY_RUNTIME_UPDATE,
      "RuntimeUpdate" },
};

value_string_entry_t m_spdm_key_exchange_mut_auth_string_table[] = {
    { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED, "MutAuthNoEncap" },
    { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_ENCAP_REQUEST,
      "MutAuthWithEncap" },
    { SPDM_KEY_EXCHANGE_RESPONSE_MUT_AUTH_REQUESTED_WITH_GET_DIGESTS,
      "MutAuthWithGetDigests" },
};

value_string_entry_t m_spdm_key_update_operation_string_table[] = {
    { SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY, "UpdateKey" },
    { SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS, "UpdateAllkeys" },
    { SPDM_KEY_UPDATE_OPERATIONS_TABLE_VERIFY_NEW_KEY, "VerifyNewKey" },
};

value_string_entry_t m_spdm_end_session_attribute_string_table[] = {
    { SPDM_END_SESSION_REQUEST_ATTRIBUTES_PRESERVE_NEGOTIATED_STATE_CLEAR,
      "PreserveStateClear" },
};

value_string_entry_t m_spdm_set_key_pair_info_operation_string_table[] = {
    { SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION, "Change" },
    { SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION, "Erase" },
    { SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION, "Generate" },
};

value_string_entry_t m_spdm_key_pair_capability_string_table[] = {
    { SPDM_KEY_PAIR_CAP_GEN_KEY_CAP, "GenKey" },
    { SPDM_KEY_PAIR_CAP_ERASABLE_CAP, "Erasable" },
    { SPDM_KEY_PAIR_CAP_CERT_ASSOC_CAP, "CertAssoc" },
    { SPDM_KEY_PAIR_CAP_KEY_USAGE_CAP, "KeyUsage" },
    { SPDM_KEY_PAIR_CAP_ASYM_ALGO_CAP, "AsymAlgo" },
    { SPDM_KEY_PAIR_CAP_SHAREABLE_CAP, "Sharable" },
};

value_string_entry_t m_spdm_key_pair_asym_algo_string_table[] = {
    { SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA2048, "RSA2048" },
    { SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA3072, "RSA3072" },
    { SPDM_KEY_PAIR_ASYM_ALGO_CAP_RSA4096, "RSA4096" },
    { SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC256, "ECC256" },
    { SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC384, "ECC384" },
    { SPDM_KEY_PAIR_ASYM_ALGO_CAP_ECC521, "ECC521" },
    { SPDM_KEY_PAIR_ASYM_ALGO_CAP_SM2, "SM2" },
    { SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED25519, "Ed25519" },
    { SPDM_KEY_PAIR_ASYM_ALGO_CAP_ED448, "Ed448" },
};

value_string_entry_t m_spdm_chunk_send_attribute_string_table[] = {
    { SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK,
      "LastChunk" },
};


value_string_entry_t m_spdm_chunk_send_ack_attribute_string_table[] = {
    { SPDM_CHUNK_SEND_ACK_RESPONSE_ATTRIBUTE_EARLY_ERROR_DETECTED,
      "EarlyErrorDetected" },
};

value_string_entry_t m_spdm_error_string_table[] = {
    { SPDM_ERROR_CODE_INVALID_REQUEST,
      "InvalidRequset" },
    { SPDM_ERROR_CODE_BUSY,
      "CodeBusy" },
    { SPDM_ERROR_CODE_UNEXPECTED_REQUEST,
      "UnexpectedRequest" },
    { SPDM_ERROR_CODE_UNSPECIFIED,
      "Unspecified" },
    { SPDM_ERROR_CODE_UNSUPPORTED_REQUEST,
      "UnsupportedRequest" },
    { SPDM_ERROR_CODE_VERSION_MISMATCH,
      "VersionMismatch" },
    { SPDM_ERROR_CODE_RESPONSE_NOT_READY,
      "ResponseNotReady" },
    { SPDM_ERROR_CODE_REQUEST_RESYNCH,
      "RequestResynch" },
    { SPDM_ERROR_CODE_VENDOR_DEFINED,
      "VendorDefined" },
    { SPDM_ERROR_CODE_INVALID_SESSION,
      "InvalidSession" },
    { SPDM_ERROR_CODE_DECRYPT_ERROR,
      "DecryptError" },
    { SPDM_ERROR_CODE_REQUEST_IN_FLIGHT,
      "RequestInFlight" },
    { SPDM_ERROR_CODE_INVALID_RESPONSE_CODE,
      "InvalidResponseCode" },
    { SPDM_ERROR_CODE_SESSION_LIMIT_EXCEEDED,
      "SessionLimitExceeded" },
    { SPDM_ERROR_CODE_SESSION_REQUIRED,
      "SessionRequired" },
    { SPDM_ERROR_CODE_RESET_REQUIRED,
      "ResetRequired" },
    { SPDM_ERROR_CODE_RESPONSE_TOO_LARGE,
      "ResponseTooLarge" },
    { SPDM_ERROR_CODE_REQUEST_TOO_LARGE,
      "RequestTooLarge" },
    { SPDM_ERROR_CODE_LARGE_RESPONSE,
      "LargeResponse" },
    { SPDM_ERROR_CODE_MESSAGE_LOST,
      "MessageLost" },
};

uint32_t spdm_dump_get_measurement_summary_hash_size(
    uint8_t measurement_summary_hash_type)
{
    /* Requester does not support measurement*/
    if (m_encapsulated) {
        return 0;
    }
    /* Check responder capabilities*/
    if ((m_spdm_responder_capabilities_flags &
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_MEAS_CAP) == 0) {
        return 0;
    }

    switch (measurement_summary_hash_type) {
    case SPDM_CHALLENGE_REQUEST_NO_MEASUREMENT_SUMMARY_HASH:
        return 0;
        break;

    case SPDM_CHALLENGE_REQUEST_TCB_COMPONENT_MEASUREMENT_HASH:
    case SPDM_CHALLENGE_REQUEST_ALL_MEASUREMENTS_HASH:
        return libspdm_get_hash_size(m_spdm_base_hash_algo);
        break;
    }

    return 0;
}

void dump_spdm_get_version(const void *buffer, size_t buffer_size)
{
    size_t message_size;

    printf("SPDM_GET_VERSION ");

    message_size = sizeof(spdm_get_version_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");

    libspdm_reset_message_a(m_spdm_context);
    libspdm_reset_message_b(m_spdm_context);
    libspdm_reset_message_c(m_spdm_context);
    libspdm_append_message_a(m_spdm_context, buffer, message_size);
}

void dump_spdm_version(const void *buffer, size_t buffer_size)
{
    size_t message_size;
    const spdm_version_response_t *spdm_response;
    spdm_version_number_t *spdm_version_number;
    size_t index;

    printf("SPDM_VERSION ");

    message_size = sizeof(spdm_version_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    message_size += spdm_response->version_number_entry_count *
                    sizeof(spdm_version_number_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        spdm_version_number =
            (void *)((size_t)buffer + sizeof(spdm_version_response_t));
        printf("(");
        for (index = 0;
             index < spdm_response->version_number_entry_count;
             index++) {
            if (index != 0) {
                printf(", ");
            }
            printf("%d.%d.%d.%d",
                   (spdm_version_number[index] >> 12) & 0xF,
                   (spdm_version_number[index] >> 8) & 0xF,
                   (spdm_version_number[index] >> 4) & 0xF,
                   spdm_version_number[index] & 0xF);
        }
        printf(") ");
    }
    printf("\n");

    libspdm_append_message_a(m_spdm_context, buffer, message_size);
}

void dump_spdm_get_capabilities(const void *buffer, size_t buffer_size)
{
    size_t message_size;
    const spdm_get_capabilities_request_t *spdm_request;
    libspdm_data_parameter_t parameter;
    spdm_version_number_t spdm_version;

    printf("SPDM_GET_CAPABILITIES ");

    message_size = offsetof(spdm_get_capabilities_request_t, reserved);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        message_size = offsetof(spdm_get_capabilities_request_t, data_transfer_size);
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }
    }

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        message_size = sizeof(spdm_get_capabilities_request_t);
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }
    }

    if (!m_param_quite_mode) {
        if (spdm_request->header.spdm_version >=
            SPDM_MESSAGE_VERSION_11) {
            printf("(Flags=0x%08x, CTExponent=0x%02x",
                   spdm_request->flags, spdm_request->ct_exponent);
            if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
                printf(", DataTransSize=0x%08x, MaxSpdmMsgSize=0x%08x",
                       spdm_request->data_transfer_size, spdm_request->max_spdm_msg_size);
            }
            printf(") ");

            if (m_param_all_mode) {
                printf("\n    Flags(");
                dump_entry_flags_all(
                    m_spdm_requester_capabilities_string_table,
                    LIBSPDM_ARRAY_SIZE(
                        m_spdm_requester_capabilities_string_table),
                    spdm_request->flags);
                printf(")");
            }
        } else {
            printf("() ");
        }
    }

    printf("\n");

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    spdm_version = (spdm_request->header.spdm_version << SPDM_VERSION_NUMBER_SHIFT_BIT);
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_SPDM_VERSION,
                     &parameter, &spdm_version,
                     sizeof(spdm_version));

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        m_spdm_requester_capabilities_flags = spdm_request->flags;

        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
        libspdm_set_data(m_spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS,
                         &parameter, &m_spdm_requester_capabilities_flags,
                         sizeof(uint32_t));
    }

    libspdm_append_message_a(m_spdm_context, buffer, message_size);
}

void dump_spdm_capabilities(const void *buffer, size_t buffer_size)
{
    size_t message_size;
    const spdm_capabilities_response_t *spdm_response;
    libspdm_data_parameter_t parameter;

    printf("SPDM_CAPABILITIES ");

    message_size = offsetof(spdm_capabilities_response_t, data_transfer_size);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        message_size = sizeof(spdm_capabilities_response_t);
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }
    }

    if (!m_param_quite_mode) {
        printf("(Flags=0x%08x, CTExponent=0x%02x",
               spdm_response->flags, spdm_response->ct_exponent);
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
            printf(", DataTransSize=0x%08x, MaxSpdmMsgSize=0x%08x",
                   spdm_response->data_transfer_size, spdm_response->max_spdm_msg_size);
        }
        printf(") ");

        if (m_param_all_mode) {
            printf("\n    Flags(");
            dump_entry_flags_all(
                m_spdm_responder_capabilities_string_table,
                LIBSPDM_ARRAY_SIZE(
                    m_spdm_responder_capabilities_string_table),
                spdm_response->flags);
            printf(")");
        }
    }

    printf("\n");

    m_spdm_responder_capabilities_flags = spdm_response->flags;

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &m_spdm_responder_capabilities_flags, sizeof(uint32_t));

    libspdm_append_message_a(m_spdm_context, buffer, message_size);
}

void dump_spdm_negotiate_algorithms(const void *buffer, size_t buffer_size)
{
    size_t message_size;
    const spdm_negotiate_algorithms_request_t *spdm_request;
    size_t index;
    spdm_negotiate_algorithms_common_struct_table_t *struct_table;
    uint8_t ext_alg_count;

    printf("SPDM_NEGOTIATE_ALGORITHMS ");

    message_size = sizeof(spdm_negotiate_algorithms_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;
    message_size +=
        spdm_request->ext_asym_count *
        sizeof(spdm_extended_algorithm_t) +
        spdm_request->ext_hash_count *
        sizeof(spdm_extended_algorithm_t) +
        spdm_request->header.param1 *
        sizeof(spdm_negotiate_algorithms_common_struct_table_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    m_multi_key_conn_rsp = false;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if ((spdm_request->other_params_support & SPDM_ALGORITHMS_MULTI_KEY_CONN) != 0) {
            m_multi_key_conn_rsp = true;
        }
    }

    if (!m_param_quite_mode) {
        printf("(MeasSpec=0x%02x(",
               spdm_request->measurement_specification);
        dump_entry_flags(
            m_spdm_measurement_spec_value_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_measurement_spec_value_string_table),
            spdm_request->measurement_specification);
        if (spdm_request->header.spdm_version >=
            SPDM_MESSAGE_VERSION_12) {
            printf("), OtherParam=0x%02x(", spdm_request->other_params_support);
            dump_entry_flags(m_spdm_other_param_value_string_table,
                             LIBSPDM_ARRAY_SIZE(m_spdm_other_param_value_string_table),
                             spdm_request->other_params_support);
        }
        printf("), Hash=0x%08x(", spdm_request->base_hash_algo);
        dump_entry_flags(m_spdm_hash_value_string_table,
                         LIBSPDM_ARRAY_SIZE(m_spdm_hash_value_string_table),
                         spdm_request->base_hash_algo);
        printf("), Asym=0x%08x(", spdm_request->base_asym_algo);
        dump_entry_flags(m_spdm_asym_value_string_table,
                         LIBSPDM_ARRAY_SIZE(m_spdm_asym_value_string_table),
                         spdm_request->base_asym_algo);
        if (spdm_request->header.spdm_version >=
            SPDM_MESSAGE_VERSION_14) {
            printf("), PqcAsym=0x%08x(", spdm_request->pqc_asym_algo);
            dump_entry_flags(m_spdm_pqc_asym_value_string_table,
                             LIBSPDM_ARRAY_SIZE(m_spdm_pqc_asym_value_string_table),
                             spdm_request->pqc_asym_algo);
        }
        if (spdm_request->header.spdm_version >=
            SPDM_MESSAGE_VERSION_13) {
            printf("), MelSpec=0x%02x(", spdm_request->mel_specification);
            dump_entry_flags(m_spdm_mel_spec_value_string_table,
                             LIBSPDM_ARRAY_SIZE(m_spdm_mel_spec_value_string_table),
                             spdm_request->mel_specification);
        }

        if (spdm_request->header.spdm_version >=
            SPDM_MESSAGE_VERSION_11) {
            struct_table =
                (void *)((size_t)buffer +
                         sizeof(spdm_negotiate_algorithms_request_t) +
                         spdm_request->ext_asym_count *
                         sizeof(spdm_extended_algorithm_t) +
                         spdm_request->ext_hash_count *
                         sizeof(spdm_extended_algorithm_t));
            for (index = 0; index < spdm_request->header.param1;
                 index++) {
                switch (struct_table->alg_type) {
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
                    printf("), DHE=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_flags(
                        m_spdm_dhe_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_dhe_value_string_table),
                        struct_table->alg_supported);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
                    printf("), AEAD=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_flags(
                        m_spdm_aead_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_aead_value_string_table),
                        struct_table->alg_supported);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
                    printf("), ReqAsym=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_flags(
                        m_spdm_asym_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_asym_value_string_table),
                        struct_table->alg_supported);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
                    printf("), KeySchedule=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_flags(
                        m_spdm_key_schedule_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_key_schedule_value_string_table),
                        struct_table->alg_supported);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG:
                    printf("), ReqPqcAsym=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_flags(
                        m_spdm_pqc_asym_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_pqc_asym_value_string_table),
                        struct_table->alg_supported);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG:
                    printf("), KEM=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_flags(
                        m_spdm_kem_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_kem_value_string_table),
                        struct_table->alg_supported);
                    break;
                }
                ext_alg_count = struct_table->alg_count & 0xF;
                struct_table =
                    (void *)((size_t)struct_table +
                             sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                             sizeof(uint32_t) *
                             ext_alg_count);
            }
        }
        printf(")) ");

        if (m_param_all_mode) {
            printf("\n    ext_hash_count(0x%02x) ext_asym_count(0x%02x)",
                   spdm_request->ext_hash_count,
                   spdm_request->ext_asym_count);
        }
    }

    printf("\n");

    libspdm_append_message_a(m_spdm_context, buffer, message_size);
}

void dump_spdm_algorithms(const void *buffer, size_t buffer_size)
{
    size_t message_size;
    const spdm_algorithms_response_t *spdm_response;
    size_t index;
    spdm_negotiate_algorithms_common_struct_table_t *struct_table;
    libspdm_data_parameter_t parameter;
    uint8_t ext_alg_count;

    printf("SPDM_ALGORITHMS ");

    message_size = sizeof(spdm_algorithms_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    message_size +=
        spdm_response->ext_asym_sel_count *
        sizeof(spdm_extended_algorithm_t) +
        spdm_response->ext_hash_sel_count *
        sizeof(spdm_extended_algorithm_t) +
        spdm_response->header.param1 *
        sizeof(spdm_negotiate_algorithms_common_struct_table_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    m_multi_key_conn_req = false;
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if ((spdm_response->other_params_selection & SPDM_ALGORITHMS_MULTI_KEY_CONN) != 0) {
            m_multi_key_conn_req = true;
        }
    }

    if (!m_param_quite_mode) {
        printf("(MeasSpec=0x%02x(",
               spdm_response->measurement_specification_sel);
        dump_entry_value(
            m_spdm_measurement_spec_value_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_measurement_spec_value_string_table),
            spdm_response->measurement_specification_sel);
        if (spdm_response->header.spdm_version >=
            SPDM_MESSAGE_VERSION_12) {
            printf("), OtherParam=0x%02x(", spdm_response->other_params_selection);
            dump_entry_flags(m_spdm_other_param_value_string_table,
                             LIBSPDM_ARRAY_SIZE(m_spdm_other_param_value_string_table),
                             spdm_response->other_params_selection);
        }
        printf("), Hash=0x%08x(", spdm_response->base_hash_sel);
        dump_entry_value(m_spdm_hash_value_string_table,
                         LIBSPDM_ARRAY_SIZE(m_spdm_hash_value_string_table),
                         spdm_response->base_hash_sel);
        printf("), MeasHash=0x%08x(",
               spdm_response->measurement_hash_algo);
        dump_entry_value(
            m_spdm_measurement_hash_value_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_measurement_hash_value_string_table),
            spdm_response->measurement_hash_algo);
        printf("), Asym=0x%08x(", spdm_response->base_asym_sel);
        dump_entry_value(m_spdm_asym_value_string_table,
                         LIBSPDM_ARRAY_SIZE(m_spdm_asym_value_string_table),
                         spdm_response->base_asym_sel);
        if (spdm_response->header.spdm_version >=
            SPDM_MESSAGE_VERSION_14) {
            printf("), PqcAsym=0x%02x(", spdm_response->pqc_asym_sel);
            dump_entry_value(m_spdm_pqc_asym_value_string_table,
                             LIBSPDM_ARRAY_SIZE(m_spdm_pqc_asym_value_string_table),
                             spdm_response->pqc_asym_sel);
        }
        if (spdm_response->header.spdm_version >=
            SPDM_MESSAGE_VERSION_13) {
            printf("), MelSpec=0x%02x(", spdm_response->mel_specification_sel);
            dump_entry_value(m_spdm_mel_spec_value_string_table,
                             LIBSPDM_ARRAY_SIZE(m_spdm_mel_spec_value_string_table),
                             spdm_response->mel_specification_sel);
        }

        if (spdm_response->header.spdm_version >=
            SPDM_MESSAGE_VERSION_11) {
            struct_table =
                (void *)((size_t)buffer +
                         sizeof(spdm_algorithms_response_t) +
                         spdm_response->ext_asym_sel_count *
                         sizeof(spdm_extended_algorithm_t) +
                         spdm_response->ext_hash_sel_count *
                         sizeof(spdm_extended_algorithm_t));
            for (index = 0; index < spdm_response->header.param1;
                 index++) {
                switch (struct_table->alg_type) {
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
                    printf("), DHE=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_value(
                        m_spdm_dhe_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_dhe_value_string_table),
                        struct_table->alg_supported);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
                    printf("), AEAD=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_value(
                        m_spdm_aead_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_aead_value_string_table),
                        struct_table->alg_supported);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
                    printf("), ReqAsym=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_value(
                        m_spdm_asym_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_asym_value_string_table),
                        struct_table->alg_supported);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
                    printf("), KeySchedule=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_value(
                        m_spdm_key_schedule_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_key_schedule_value_string_table),
                        struct_table->alg_supported);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG:
                    printf("), ReqPqcAsym=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_value(
                        m_spdm_pqc_asym_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_pqc_asym_value_string_table),
                        struct_table->alg_supported);
                    break;
                case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG:
                    printf("), KEM=0x%04x(",
                           struct_table->alg_supported);
                    dump_entry_value(
                        m_spdm_kem_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_kem_value_string_table),
                        struct_table->alg_supported);
                    break;
                }
                ext_alg_count = struct_table->alg_count & 0xF;
                struct_table =
                    (void *)((size_t)struct_table +
                             sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                             sizeof(uint32_t) *
                             ext_alg_count);
            }
        }
        printf(")) ");

        if (m_param_all_mode) {
            printf("\n    ExtHashCount(0x%02x) ExtAsymCount(0x%02x)",
                   spdm_response->ext_hash_sel_count,
                   spdm_response->ext_asym_sel_count);
        }
    }

    printf("\n");

    m_spdm_measurement_spec = spdm_response->measurement_specification_sel;
    m_spdm_measurement_hash_algo = spdm_response->measurement_hash_algo;
    m_spdm_base_asym_algo = spdm_response->base_asym_sel;
    m_spdm_base_hash_algo = spdm_response->base_hash_sel;
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
        m_spdm_pqc_asym_algo = spdm_response->pqc_asym_sel;
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        struct_table =
            (void *)((size_t)buffer +
                     sizeof(spdm_algorithms_response_t) +
                     spdm_response->ext_asym_sel_count *
                     sizeof(spdm_extended_algorithm_t) +
                     spdm_response->ext_hash_sel_count *
                     sizeof(spdm_extended_algorithm_t));
        for (index = 0; index < spdm_response->header.param1; index++) {
            switch (struct_table->alg_type) {
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_DHE:
                m_spdm_dhe_named_group =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_AEAD:
                m_spdm_aead_cipher_suite =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_BASE_ASYM_ALG:
                m_spdm_req_base_asym_alg =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEY_SCHEDULE:
                m_spdm_key_schedule =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_REQ_PQC_ASYM_ALG:
                m_spdm_req_pqc_asym_alg =
                    struct_table->alg_supported;
                break;
            case SPDM_NEGOTIATE_ALGORITHMS_STRUCT_TABLE_ALG_TYPE_KEM_ALG:
                m_spdm_kem_alg =
                    struct_table->alg_supported;
                break;
            }
            ext_alg_count = struct_table->alg_count & 0xF;
            struct_table =
                (void *)((size_t)struct_table +
                         sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                         sizeof(uint32_t) * ext_alg_count);
        }
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        m_spdm_other_params_support = spdm_response->other_params_selection;
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            m_spdm_mel_spec = spdm_response->mel_specification_sel;
        }
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &m_spdm_measurement_spec, sizeof(uint8_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
                     &parameter, &m_spdm_measurement_hash_algo,
                     sizeof(uint32_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &m_spdm_base_asym_algo, sizeof(uint32_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &m_spdm_base_hash_algo, sizeof(uint32_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_PQC_ASYM_ALGO, &parameter,
                     &m_spdm_pqc_asym_algo, sizeof(uint32_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &m_spdm_dhe_named_group, sizeof(uint16_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &m_spdm_aead_cipher_suite, sizeof(uint16_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &m_spdm_req_base_asym_alg, sizeof(uint16_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter,
                     &m_spdm_key_schedule, sizeof(uint16_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &m_spdm_other_params_support, sizeof(uint8_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_MEL_SPEC, &parameter,
                     &m_spdm_mel_spec, sizeof(uint8_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_REQ_PQC_ASYM_ALG, &parameter,
                     &m_spdm_req_pqc_asym_alg, sizeof(uint32_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_KEM_ALG, &parameter,
                     &m_spdm_kem_alg, sizeof(uint32_t));

    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_MULTI_KEY_CONN_REQ, &parameter,
                     &m_multi_key_conn_req, sizeof(bool));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_MULTI_KEY_CONN_RSP, &parameter,
                     &m_multi_key_conn_rsp, sizeof(bool));

    libspdm_append_message_a(m_spdm_context, buffer, message_size);
}

void dump_spdm_get_digests(const void *buffer, size_t buffer_size)
{
    size_t message_size;

    printf("SPDM_GET_DIGESTS ");

    message_size = sizeof(spdm_get_digest_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_digests(const void *buffer, size_t buffer_size)
{
    const spdm_digest_response_t *spdm_response;
    size_t message_size;
    size_t hash_size;
    size_t slot_count;
    size_t index;
    uint8_t *digest;
    size_t additional_size;
    spdm_key_pair_id_t *key_pair_id;
    spdm_certificate_info_t *cert_info;
    spdm_key_usage_bit_mask_t *key_usage_bit_mask;

    printf("SPDM_DIGESTS ");

    message_size = sizeof(spdm_digest_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;

    slot_count = 0;
    for (index = 0; index < 8; index++) {
        if (((1 << index) & spdm_response->header.param2) != 0) {
            slot_count++;
        }
    }

    additional_size = 0;
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        if (((!m_encapsulated) && m_multi_key_conn_rsp) ||
            (m_encapsulated && m_multi_key_conn_req)) {
            additional_size = sizeof(spdm_key_pair_id_t) + sizeof(spdm_certificate_info_t) +
                              sizeof(spdm_key_usage_bit_mask_t);
        }
    }

    hash_size = libspdm_get_hash_size(m_spdm_base_hash_algo);

    message_size += slot_count * (hash_size + additional_size);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(");
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            printf("SupportedSlotMask=0x%02x, ", spdm_response->header.param1);
        }
        printf("ProvisionedSlotMask=0x%02x) ", spdm_response->header.param2);

        digest = (void *)(spdm_response + 1);
        key_pair_id =
            (spdm_key_pair_id_t *)((uint8_t *)digest + hash_size * slot_count);
        cert_info =
            (spdm_certificate_info_t *)((uint8_t *)key_pair_id + sizeof(spdm_key_pair_id_t) *
                                        slot_count);
        key_usage_bit_mask =
            (spdm_key_usage_bit_mask_t *)((uint8_t *)cert_info + sizeof(spdm_certificate_info_t) *
                                          slot_count);
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            if (((!m_encapsulated) && m_multi_key_conn_rsp) ||
                (m_encapsulated && m_multi_key_conn_req)) {
                printf("(KeyPairId=");
                for (index = 0; index < slot_count; index++) {
                    printf("0x%02x,", key_pair_id[index]);
                }
                printf(" CertInfo=");
                for (index = 0; index < slot_count; index++) {
                    printf("0x%02x(", cert_info[index]);
                    dump_entry_value(
                        m_spdm_cert_model_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_cert_model_string_table),
                        cert_info[index] & SPDM_CERTIFICATE_INFO_CERT_MODEL_MASK);
                    printf("),");
                }
                printf(" KeyUsage=");
                for (index = 0; index < slot_count; index++) {
                    printf("0x%04x(", key_usage_bit_mask[index]);
                    dump_entry_flags(
                        m_spdm_key_usage_value_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_key_usage_value_string_table),
                        key_usage_bit_mask[index]);
                    printf("),");
                }
                printf(") ");
            }
        }

        if (m_param_all_mode) {
            for (index = 0; index < slot_count; index++) {
                printf("\n    Digest_%d(", (uint32_t)index);
                dump_data(digest, hash_size);
                printf(")");
                digest += hash_size;
            }
        }
    }

    if (!m_encapsulated) {
        if (m_multi_key_conn_rsp) {
            libspdm_append_message_d(m_spdm_context, buffer, message_size);
        }
    } else {
        if (m_multi_key_conn_req && (m_current_session_info != NULL)) {
            libspdm_append_message_encap_d(m_spdm_context, m_current_session_info, true,
                                           buffer, message_size);
        }
    }
    printf("\n");
}

void dump_spdm_get_certificate(const void *buffer, size_t buffer_size)
{
    const spdm_get_certificate_large_request_t *spdm_request;
    size_t message_size;
    bool use_large_cert_chain;
    size_t req_msg_length;
    size_t req_msg_offset;

    printf("SPDM_GET_CERTIFICATE ");

    message_size = sizeof(spdm_get_certificate_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if ((spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_14) &&
        ((spdm_request->header.param1 & SPDM_GET_CERTIFICATE_REQUEST_LARGE_CERT_CHAIN) != 0)) {
        use_large_cert_chain = true;
    } else {
        use_large_cert_chain = false;
    }

    if (use_large_cert_chain) {
        message_size = sizeof(spdm_get_certificate_large_request_t);
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }
        req_msg_length = spdm_request->large_length;
        req_msg_offset = spdm_request->large_offset;
    } else {
        req_msg_length = spdm_request->length;
        req_msg_offset = spdm_request->offset;
    }

    if (!m_param_quite_mode) {
        printf("(SlotID=0x%02x", spdm_request->header.param1 & SPDM_GET_CERTIFICATE_REQUEST_SLOT_ID_MASK);
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
            printf(", LargeCert=0x%02x", spdm_request->header.param1 & SPDM_GET_CERTIFICATE_REQUEST_LARGE_CERT_CHAIN);
        }
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            printf(", Attr=0x%02x(", spdm_request->header.param2);
            dump_entry_flags(
                m_spdm_get_cert_attribute_string_table,
                LIBSPDM_ARRAY_SIZE(m_spdm_get_cert_attribute_string_table),
                spdm_request->header.param2);
            printf(")");
        }
        if (use_large_cert_chain) {
            printf(", Offset=0x%08x, Length=0x%08x) ", (uint32_t)req_msg_offset, (uint32_t)req_msg_length);
        } else {
            printf(", Offset=0x%04x, Length=0x%04x) ", (uint16_t)req_msg_offset, (uint16_t)req_msg_length);
        }
    }

    m_cached_spdm_cert_chain_buffer_offset = req_msg_offset;

    printf("\n");
}

void dump_spdm_certificate(const void *buffer, size_t buffer_size)
{
    const spdm_certificate_large_response_t *spdm_response;
    size_t message_size;
    void *cert_chain;
    size_t cert_chain_size;
    size_t hash_size;
    spdm_cert_chain_t *spdm_cert_chain;
    uint8_t *root_hash;
    size_t cert_chain_offset;
    bool use_large_cert_chain;
    size_t rsp_msg_portion_length;
    size_t rsp_msg_remainder_length;
    size_t rsp_msg_header_size;
    uint8_t slot_id;

    printf("SPDM_CERTIFICATE ");

    message_size = sizeof(spdm_certificate_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;

    if ((spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) &&
        ((spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_LARGE_CERT_CHAIN) != 0)) {
        use_large_cert_chain = true;
    } else {
        use_large_cert_chain = false;
    }

    if (use_large_cert_chain) {
        message_size = sizeof(spdm_certificate_large_response_t);
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }
        rsp_msg_portion_length = spdm_response->large_portion_length;
        rsp_msg_remainder_length = spdm_response->large_remainder_length;
        rsp_msg_header_size = sizeof(spdm_certificate_large_response_t);
    } else {
        rsp_msg_portion_length = spdm_response->portion_length;
        rsp_msg_remainder_length = spdm_response->remainder_length;
        rsp_msg_header_size = sizeof(spdm_certificate_response_t);
    }

    message_size += rsp_msg_portion_length;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(SlotID=0x%02x", spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_SLOT_ID_MASK);
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_14) {
            printf(", LargeCert=0x%02x", spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_LARGE_CERT_CHAIN);
        }
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            printf(", Attr=0x%02x(", spdm_response->header.param2);
            dump_entry_value(
                m_spdm_cert_model_string_table,
                LIBSPDM_ARRAY_SIZE(m_spdm_cert_model_string_table),
                spdm_response->header.param2 &
                SPDM_CERTIFICATE_RESPONSE_ATTRIBUTES_CERTIFICATE_INFO_MASK);
            printf(")");
        }
        if (use_large_cert_chain) {
            printf(", PortLen=0x%08x, RemLen=0x%08x) ",
                   (uint32_t)rsp_msg_portion_length, (uint32_t)rsp_msg_remainder_length);
        } else {
            printf(", PortLen=0x%04x, RemLen=0x%04x) ",
                   (uint16_t)rsp_msg_portion_length, (uint16_t)rsp_msg_remainder_length);
        }
    }

    if (m_cached_spdm_cert_chain_buffer_offset +
        rsp_msg_portion_length >
        LIBSPDM_MAX_CERT_CHAIN_SIZE) {
        printf(
            "SPDM cert_chain is too larger. Please increase LIBSPDM_MAX_CERT_CHAIN_SIZE and rebuild.\n");
        exit(0);
    }
    memcpy((uint8_t *)m_spdm_cert_chain_buffer +
           m_cached_spdm_cert_chain_buffer_offset,
           (uint8_t *)spdm_response + rsp_msg_header_size, rsp_msg_portion_length);
    m_spdm_cert_chain_buffer_size = m_cached_spdm_cert_chain_buffer_offset +
                                    rsp_msg_portion_length;

    hash_size = libspdm_get_hash_size(m_spdm_base_hash_algo);

    if (rsp_msg_remainder_length == 0) {
        if (m_spdm_cert_chain_buffer_size <=
            sizeof(spdm_cert_chain_t) + hash_size) {
            printf("\n");
            return;
        }

        spdm_cert_chain = m_spdm_cert_chain_buffer;
        if (spdm_cert_chain->length != m_spdm_cert_chain_buffer_size) {
            printf("\n");
            return;
        }
    }

    if (!m_param_quite_mode) {
        if (m_param_all_mode) {
            if (rsp_msg_remainder_length == 0) {
                spdm_cert_chain = m_spdm_cert_chain_buffer;
                printf("\n    SpdmCertChainSize(0x%04x)",
                       spdm_cert_chain->length);

                root_hash = (void *)(spdm_cert_chain + 1);
                printf("\n    RootHash(");
                dump_data(root_hash, hash_size);
                printf(")");

                cert_chain = (uint8_t *)m_spdm_cert_chain_buffer +
                             sizeof(spdm_cert_chain_t) +
                             hash_size;
                cert_chain_size =
                    m_spdm_cert_chain_buffer_size -
                    (sizeof(spdm_cert_chain_t) + hash_size);
                printf("\n    CertChain(\n");
                dump_hex(cert_chain, cert_chain_size);
                printf("    )");
            }
        }
    }

    if (rsp_msg_remainder_length == 0) {
        cert_chain = (uint8_t *)m_spdm_cert_chain_buffer;
        cert_chain_size = m_spdm_cert_chain_buffer_size;

        if (spdm_response->header.param1 >= SPDM_MAX_SLOT_COUNT) {
            printf("spdm_response->header.param1 is not right\n");
            return;
        }

        if (m_cert_chain_format == CERT_CHAIN_FORMAT_SPDM) {
            cert_chain_offset = 0;
        } else {
            cert_chain_offset = sizeof(spdm_cert_chain_t) + hash_size;
        }

        /* override rule: alway record the latest data */
        slot_id = spdm_response->header.param1 & SPDM_CERTIFICATE_RESPONSE_SLOT_ID_MASK;
        if (m_encapsulated) {
            if (m_param_out_rsq_cert_chain_file_name[slot_id] != NULL) {
                if (!write_output_file(
                        m_param_out_rsq_cert_chain_file_name[slot_id],
                        (uint8_t *)cert_chain + cert_chain_offset,
                        cert_chain_size - cert_chain_offset)) {
                    printf("Fail to write out_req_cert_chain\n");
                }
            }
            if (m_requester_cert_chain_buffer[slot_id] != NULL) {
                free (m_requester_cert_chain_buffer[slot_id]);
            }
            m_requester_cert_chain_buffer[slot_id] =
                malloc(cert_chain_size);
            if (m_requester_cert_chain_buffer[slot_id] != NULL) {
                memcpy(m_requester_cert_chain_buffer[slot_id],
                       cert_chain, cert_chain_size);
                m_requester_cert_chain_buffer_size[slot_id] =
                    cert_chain_size;
            }
        } else {
            if (m_param_out_rsp_cert_chain_file_name[slot_id] != NULL) {
                if (!write_output_file(
                        m_param_out_rsp_cert_chain_file_name[slot_id],
                        (uint8_t *)cert_chain + cert_chain_offset,
                        cert_chain_size - cert_chain_offset)) {
                    printf("Fail to write out_rsp_cert_chain\n");
                }
            }
            if (m_responder_cert_chain_buffer[slot_id] != NULL) {
                free (m_responder_cert_chain_buffer[slot_id]);
            }
            m_responder_cert_chain_buffer[slot_id] =
                malloc(cert_chain_size);
            if (m_responder_cert_chain_buffer[slot_id] != NULL) {
                memcpy(m_responder_cert_chain_buffer[slot_id],
                       cert_chain, cert_chain_size);
                m_responder_cert_chain_buffer_size[slot_id] =
                    cert_chain_size;
            }
        }
    }

    printf("\n");
}

void dump_spdm_challenge(const void *buffer, size_t buffer_size)
{
    const spdm_challenge_request_t *spdm_request;
    size_t message_size;

    printf("SPDM_CHALLENGE ");

    message_size = sizeof(spdm_challenge_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        message_size = sizeof(spdm_challenge_request_t) + SPDM_REQ_CONTEXT_SIZE;
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }
    }

    m_cached_measurement_summary_hash_type = spdm_request->header.param2;

    if (!m_param_quite_mode) {
        printf("(SlotID=0x%02x, HashType=0x%02x(",
               spdm_request->header.param1,
               spdm_request->header.param2);
        dump_entry_value(
            m_spdm_request_hash_type_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_request_hash_type_string_table),
            spdm_request->header.param2);
        printf(")) ");

        if (m_param_all_mode) {
            printf("\n    Nonce(");
            dump_data(spdm_request->nonce, SPDM_NONCE_SIZE);
            printf(")");
            if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
                printf("\n    ReqContext(");
                dump_data((uint8_t *)(spdm_request + 1), SPDM_REQ_CONTEXT_SIZE);
                printf(")");
            }
        }
    }

    printf("\n");
}

void dump_spdm_challenge_auth(const void *buffer, size_t buffer_size)
{
    const spdm_challenge_auth_response_t *spdm_response;
    size_t message_size;
    size_t hash_size;
    size_t measurement_summary_hash_size;
    size_t signature_size;
    uint16_t opaque_length;
    uint8_t *cert_chain_hash;
    uint8_t *nonce;
    uint8_t *measurement_summary_hash;
    uint8_t *opaque_data;
    uint8_t *req_context;
    uint8_t *signature;

    printf("SPDM_CHALLENGE_AUTH ");

    hash_size = libspdm_get_hash_size(m_spdm_base_hash_algo);
    if (m_encapsulated) {
        if (m_spdm_req_base_asym_alg != 0) {
            signature_size = libspdm_get_req_asym_signature_size(m_spdm_req_base_asym_alg);
        }
        if (m_spdm_req_pqc_asym_alg != 0) {
            signature_size = libspdm_get_req_pqc_asym_signature_size(m_spdm_req_pqc_asym_alg);
        }
    } else {
        if (m_spdm_base_asym_algo != 0) {
            signature_size = libspdm_get_asym_signature_size(m_spdm_base_asym_algo);
        }
        if (m_spdm_pqc_asym_algo != 0) {
            signature_size = libspdm_get_pqc_asym_signature_size(m_spdm_pqc_asym_algo);
        }
    }
    measurement_summary_hash_size =
        spdm_dump_get_measurement_summary_hash_size(
            m_cached_measurement_summary_hash_type);

    message_size = sizeof(spdm_challenge_auth_response_t) + hash_size + SPDM_NONCE_SIZE +
                   measurement_summary_hash_size + sizeof(uint16_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    opaque_length =
        *(uint16_t *)((size_t)buffer +
                      sizeof(spdm_challenge_auth_response_t) + hash_size +
                      SPDM_NONCE_SIZE + measurement_summary_hash_size);
    message_size += opaque_length + signature_size;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        message_size += + SPDM_REQ_CONTEXT_SIZE;
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }
    }

    if (!m_param_quite_mode) {
        printf("(Attr=0x%02x(", spdm_response->header.param1);
        dump_entry_flags(
            m_spdm_challenge_auth_attribute_string_table,
            LIBSPDM_ARRAY_SIZE(
                m_spdm_challenge_auth_attribute_string_table),
            spdm_response->header.param1 & 0xF0);
        printf(", SlotID=0x%02x), SlotMask=0x%02x) ",
               spdm_response->header.param1 & 0xF,
               spdm_response->header.param2);

        if (m_param_all_mode) {
            cert_chain_hash = (void *)(spdm_response + 1);
            printf("\n    CertChainHash(");
            dump_data(cert_chain_hash, hash_size);
            printf(")");
            nonce = cert_chain_hash + hash_size;
            printf("\n    Nonce(");
            dump_data(nonce, SPDM_NONCE_SIZE);
            printf(")");
            measurement_summary_hash = nonce + SPDM_NONCE_SIZE;
            if (measurement_summary_hash_size != 0) {
                printf("\n    MeasurementSummaryHash(");
                dump_data(measurement_summary_hash,
                          measurement_summary_hash_size);
                printf(")");
            }
            opaque_length =
                *(uint16_t *)(measurement_summary_hash +
                              measurement_summary_hash_size);
            opaque_data = measurement_summary_hash +
                          measurement_summary_hash_size +
                          sizeof(uint16_t);
            printf("\n    OpaqueData(");
            dump_data(opaque_data, opaque_length);
            printf(")");
            dump_spdm_opaque_data(spdm_response->header.spdm_version,
                                  opaque_data, opaque_length);
            if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
                req_context = opaque_data + opaque_length;
                printf("\n    ReqContext(");
                dump_data(req_context, SPDM_REQ_CONTEXT_SIZE);
                printf(")");
                signature = req_context + SPDM_REQ_CONTEXT_SIZE;
            } else {
                signature = opaque_data + opaque_length;
            }
            printf("\n    Signature(");
            dump_data(signature, signature_size);
            printf(")");
        }
    }

    printf("\n");
}

void dump_spdm_get_measurements(const void *buffer, size_t buffer_size)
{
    const spdm_get_measurements_request_t *spdm_request;
    size_t message_size;
    bool include_signature;
    uint8_t *req_context;

    printf("SPDM_GET_MEASUREMENTS ");

    message_size = offsetof(spdm_get_measurements_request_t, nonce);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;
    include_signature =
        ((spdm_request->header.param1 &
          SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
         0);
    if (include_signature) {
        if (spdm_request->header.spdm_version >=
            SPDM_MESSAGE_VERSION_11) {
            message_size = sizeof(spdm_get_measurements_request_t);
        } else {
            message_size = offsetof(
                spdm_get_measurements_request_t, slot_id_param);
        }
    }
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }
    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        req_context = (uint8_t *)spdm_request + message_size;
        message_size = message_size + SPDM_REQ_CONTEXT_SIZE;
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }
    } else {
        req_context = NULL;
    }

    m_cached_get_measurement_request_attribute =
        spdm_request->header.param1;
    m_cached_get_measurement_operation = spdm_request->header.param2;

    if (!m_param_quite_mode) {
        printf("(Attr=0x%02x(", spdm_request->header.param1);
        dump_entry_flags(
            m_spdm_measurement_attribute_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_measurement_attribute_string_table),
            spdm_request->header.param1);
        printf("), MeasOp=0x%02x", spdm_request->header.param2);
        switch (spdm_request->header.param2) {
        case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS:
            printf("(TotalNum)");
            break;
        case SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS:
            printf("(All)");
            break;
        }
        if (include_signature && (spdm_request->header.spdm_version >=
                                  SPDM_MESSAGE_VERSION_11)) {
            printf(", SlotID=0x%02x", spdm_request->slot_id_param);
        }
        printf(") ");

        if (m_param_all_mode) {
            if (include_signature) {
                printf("\n    Nonce(");
                dump_data(spdm_request->nonce, SPDM_NONCE_SIZE);
                printf(")");
            }
            if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
                printf("\n    ReqContext(");
                dump_data(req_context, SPDM_REQ_CONTEXT_SIZE);
                printf(")");
            }
        }
    }

    printf("\n");
}

void dump_spdm_measurements_record(uint8_t number_of_blocks,
                                   const void *measurement_record,
                                   uint32_t measurement_record_length)
{
    spdm_measurement_block_dmtf_t *dmtf_block;
    size_t index;
    size_t end_of_block;
    size_t end_of_record;

    end_of_record = (size_t)measurement_record + measurement_record_length;

    dmtf_block = (void *)measurement_record;
    for (index = 0; index < number_of_blocks; index++) {
        if ((size_t)dmtf_block + sizeof(spdm_measurement_block_dmtf_t) >
            end_of_record) {
            break;
        }
        if (dmtf_block->measurement_block_common_header
            .measurement_specification !=
            SPDM_MEASUREMENT_SPECIFICATION_DMTF) {
            break;
        }
        if (dmtf_block->measurement_block_common_header
            .measurement_size !=
            dmtf_block->measurement_block_dmtf_header
            .dmtf_spec_measurement_value_size +
            sizeof(spdm_measurement_block_dmtf_header_t)) {
            break;
        }
        end_of_block = (size_t)dmtf_block +
                       dmtf_block->measurement_block_common_header
                       .measurement_size +
                       sizeof(spdm_measurement_block_common_header_t);
        if (end_of_block > end_of_record) {
            break;
        }

        printf("\n      MeasurementRecord_%d(", (uint32_t)index);
        printf("\n        CommonHeader(Index=0x%02x, MeasSpec=0x%02x(",
               dmtf_block->measurement_block_common_header.index,
               dmtf_block->measurement_block_common_header
               .measurement_specification);
        dump_entry_flags(
            m_spdm_measurement_spec_value_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_measurement_spec_value_string_table),
            dmtf_block->measurement_block_common_header
            .measurement_specification);
        printf("), size=0x%04x)",
               dmtf_block->measurement_block_common_header
               .measurement_size);

        printf("\n        DmtfHeader(Type=0x%02x(",
               dmtf_block->measurement_block_dmtf_header
               .dmtf_spec_measurement_value_type);
        dump_entry_value(
            m_spdm_measurement_type_value_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_measurement_type_value_string_table),
            dmtf_block->measurement_block_dmtf_header
            .dmtf_spec_measurement_value_type &
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_MASK);
        if (dmtf_block->measurement_block_dmtf_header
            .dmtf_spec_measurement_value_type &
            SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM) {
            printf(", RawBitStream");
        }
        printf("), Size=0x%04x)",
               dmtf_block->measurement_block_dmtf_header
               .dmtf_spec_measurement_value_size);

        printf("\n        Value(");
        dump_data((void *)(dmtf_block + 1),
                  dmtf_block->measurement_block_dmtf_header
                  .dmtf_spec_measurement_value_size);
        printf(")");

        switch (dmtf_block->measurement_block_dmtf_header
                .dmtf_spec_measurement_value_type) {
        case (SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_SECURE_VERSION_NUMBER |
              SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM):
            if (dmtf_block->measurement_block_dmtf_header
                .dmtf_spec_measurement_value_size ==
                sizeof(spdm_measurements_secure_version_number_t)) {
                spdm_measurements_secure_version_number_t svn;
                libspdm_copy_mem((void *)&svn, sizeof(svn), (void *)(dmtf_block + 1), sizeof(svn));
                printf("\n          Svn(0x%08x%08x)", (uint32_t)(svn >> 32), (uint32_t)svn);
            }
            break;
        case (SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_DEVICE_MODE |
              SPDM_MEASUREMENT_BLOCK_MEASUREMENT_TYPE_RAW_BIT_STREAM):
            if (dmtf_block->measurement_block_dmtf_header
                .dmtf_spec_measurement_value_size ==
                sizeof(spdm_measurements_device_mode_t)) {
                spdm_measurements_device_mode_t device_mode;
                libspdm_copy_mem((void *)&device_mode, sizeof(device_mode),
                                 (void *)(dmtf_block + 1), sizeof(device_mode));
                printf("\n          DeviceMode(OpCap=0x%08x(",
                       device_mode.operational_mode_capabilities);
                dump_entry_flags(
                    m_spdm_measurement_device_operation_mode_value_string_table,
                    LIBSPDM_ARRAY_SIZE(m_spdm_measurement_device_operation_mode_value_string_table),
                    device_mode.operational_mode_capabilities);
                printf("), OpStat=0x%08x(", device_mode.operational_mode_state);
                dump_entry_flags(
                    m_spdm_measurement_device_operation_mode_value_string_table,
                    LIBSPDM_ARRAY_SIZE(m_spdm_measurement_device_operation_mode_value_string_table),
                    device_mode.operational_mode_state);
                printf("), ModCap=0x%08x(", device_mode.device_mode_capabilities);
                dump_entry_flags(
                    m_spdm_measurement_device_mode_value_string_table,
                    LIBSPDM_ARRAY_SIZE(m_spdm_measurement_device_mode_value_string_table),
                    device_mode.device_mode_capabilities);
                printf("), ModStat=0x%08x(", device_mode.device_mode_state);
                dump_entry_flags(
                    m_spdm_measurement_device_mode_value_string_table,
                    LIBSPDM_ARRAY_SIZE(m_spdm_measurement_device_mode_value_string_table),
                    device_mode.device_mode_state);
                printf("))");
            }
            break;
        default:
            break;
        }

        printf("\n        )");

        dmtf_block = (void *)end_of_block;
    }
}

void dump_spdm_measurements(const void *buffer, size_t buffer_size)
{
    const spdm_measurements_response_t *spdm_response;
    size_t message_size;
    uint32_t measurement_record_length;
    size_t signature_size;
    uint16_t opaque_length;
    bool include_signature;
    uint8_t *measurement_record;
    uint8_t *nonce;
    uint8_t *opaque_data;
    uint8_t *req_context;
    uint8_t *signature;

    printf("SPDM_MEASUREMENTS ");

    message_size = sizeof(spdm_measurements_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    include_signature =
        ((m_cached_get_measurement_request_attribute &
          SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE) !=
         0);

    spdm_response = buffer;

    measurement_record_length =
        libspdm_read_uint24(spdm_response->measurement_record_length);
    message_size += measurement_record_length;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    message_size += SPDM_NONCE_SIZE + sizeof(uint16_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    opaque_length =
        *(uint16_t *)((size_t)buffer +
                      sizeof(spdm_measurements_response_t) +
                      measurement_record_length + SPDM_NONCE_SIZE);
    message_size += opaque_length;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
        message_size += SPDM_REQ_CONTEXT_SIZE;
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }
    }

    if (include_signature) {
        if (m_spdm_base_asym_algo != 0) {
            signature_size = libspdm_get_asym_signature_size(m_spdm_base_asym_algo);
        }
        if (m_spdm_pqc_asym_algo != 0) {
            signature_size = libspdm_get_asym_signature_size(m_spdm_pqc_asym_algo);
        }
        message_size += signature_size;
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }
    }

    if (!m_param_quite_mode) {
        if (m_cached_get_measurement_operation ==
            SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
            printf("(TotalMeasIndex=0x%02x",
                   spdm_response->header.param1);
            if (include_signature) {
                if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
                    printf(", ContentChange=0x%02x(",
                           spdm_response->header.param2 &
                           SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_MASK);
                    dump_entry_value(
                        m_spdm_measurement_content_change_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_measurement_content_change_string_table),
                        spdm_response->header.param2 &
                        SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_MASK);
                    printf(")");
                }
                printf(", SlotID=0x%02x",
                       spdm_response->header.param2 & 0xF);
            }
            printf(") ");
        } else {
            printf("(NumOfBlocks=0x%02x, MeasRecordLen=0x%08x",
                   spdm_response->number_of_blocks,
                   measurement_record_length);
            if (include_signature) {
                if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
                    printf(", ContentChange=0x%02x(",
                           spdm_response->header.param2 &
                           SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_MASK);
                    dump_entry_value(
                        m_spdm_measurement_content_change_string_table,
                        LIBSPDM_ARRAY_SIZE(
                            m_spdm_measurement_content_change_string_table),
                        spdm_response->header.param2 &
                        SPDM_MEASUREMENTS_RESPONSE_CONTENT_CHANGE_MASK);
                    printf(")");
                }
                printf(", SlotID=0x%02x",
                       spdm_response->header.param2 & 0xF);
            }
            printf(") ");
        }

        if (m_param_all_mode) {
            measurement_record = (void *)(spdm_response + 1);
            if (m_cached_get_measurement_operation !=
                SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS) {
                printf("\n    MeasurementRecord(");
                dump_data(measurement_record,
                          measurement_record_length);
                printf(")");

                dump_spdm_measurements_record(
                    spdm_response->number_of_blocks,
                    measurement_record,
                    measurement_record_length);
            }
            nonce = measurement_record +
                    measurement_record_length;
            printf("\n    Nonce(");
            dump_data(nonce, SPDM_NONCE_SIZE);
            printf(")");
            opaque_length = *(uint16_t *)(nonce + SPDM_NONCE_SIZE);
            opaque_data = nonce + SPDM_NONCE_SIZE + sizeof(uint16_t);
            printf("\n    OpaqueData(");
            dump_data(opaque_data, opaque_length);
            printf(")");
            dump_spdm_opaque_data(spdm_response->header.spdm_version,
                                  opaque_data, opaque_length);
            if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
                req_context = opaque_data + opaque_length;
                printf("\n    ReqContext(");
                dump_data(req_context, SPDM_REQ_CONTEXT_SIZE);
                printf(")");
                signature = req_context + SPDM_REQ_CONTEXT_SIZE;
            } else {
                signature = opaque_data + opaque_length;
            }
            if (include_signature) {
                printf("\n    Signature(");
                dump_data(signature, signature_size);
                printf(")");
            }
        }
    }

    printf("\n");
}

void dump_spdm_get_mel(const void *buffer, size_t buffer_size)
{
    const spdm_get_measurement_extension_log_request_t *spdm_request;
    size_t message_size;

    printf("SPDM_GET_MEASUREMENT_EXTENSION_LOG ");

    message_size = sizeof(spdm_get_measurement_extension_log_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (!m_param_quite_mode) {
        printf("(Offset=0x%08x, Length=0x%08x) ",
               spdm_request->offset, spdm_request->length);
    }

    m_cached_spdm_mel_buffer_offset = spdm_request->offset;

    printf("\n");
}

void dump_spdm_mel(const void *buffer, size_t buffer_size)
{
    const spdm_measurement_extension_log_response_t *spdm_response;
    size_t message_size;
    spdm_measurement_extension_log_dmtf_t *spdm_mel;
    spdm_mel_entry_dmtf_t *mel_entry;
    uint32_t mel_index;
    uint8_t *mel_entry_value;

    printf("SPDM_MEASUREMENT_EXTENSION_LOG ");

    message_size = sizeof(spdm_measurement_extension_log_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    message_size += spdm_response->portion_length;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(PortLen=0x%08x, RemLen=0x%08x) ",
               spdm_response->portion_length,
               spdm_response->remainder_length);
    }

    if (m_cached_spdm_mel_buffer_offset + spdm_response->portion_length >
        LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE) {
        printf(
            "SPDM MEL is too larger. Please increase LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE and rebuild.\n");
        exit(0);
    }
    memcpy((uint8_t *)m_spdm_mel_buffer +
           m_cached_spdm_mel_buffer_offset,
           (spdm_response + 1), spdm_response->portion_length);
    m_spdm_mel_buffer_size = m_cached_spdm_mel_buffer_offset +
                             spdm_response->portion_length;
    spdm_mel = m_spdm_mel_buffer;

    if (!m_param_quite_mode) {
        if (m_param_all_mode) {
            if (m_spdm_mel_buffer_size >= spdm_mel->mel_entries_len + sizeof(spdm_measurement_extension_log_dmtf_t)) {
                printf("\n    SpdmMelNumber(0x%08x)",
                       spdm_mel->number_of_entries);
                printf("\n    SpdmMelTotalLen(0x%08x)",
                       spdm_mel->mel_entries_len);

                mel_entry = (spdm_mel_entry_dmtf_t *)(spdm_mel + 1);
                for (mel_index = 0; mel_index < spdm_mel->number_of_entries; mel_index++) {
                    printf("\n    MelEntry_%d(", mel_index);
                    printf("MelIndex=0x%08x,", mel_entry->mel_index);
                    printf("MeasIndex=0x%08x,", mel_entry->meas_index);
                    printf("\n        Value(");
                    mel_entry_value = (uint8_t *)(mel_entry + 1);
                    dump_data(mel_entry_value, mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);
                    mel_entry = (spdm_mel_entry_dmtf_t *)((uint8_t *)(mel_entry + 1) +
                                                           mel_entry->measurement_block_dmtf_header.dmtf_spec_measurement_value_size);
                    printf(")");
                    printf("\n    )");
                }

            }
        }
    }

    printf("\n");
}

void dump_spdm_respond_if_ready(const void *buffer, size_t buffer_size)
{
    const spdm_response_if_ready_request_t *spdm_request;

    printf("SPDM_RESPOND_IF_READY ");
    if (buffer_size < sizeof(spdm_response_if_ready_request_t)) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (!m_param_quite_mode) {
        printf("(ReqCode=0x%02x, Token=0x%02x) ",
               spdm_request->header.param1,
               spdm_request->header.param2);
    }

    printf("\n");
}

void dump_spdm_error(const void *buffer, size_t buffer_size)
{
    const spdm_error_response_t *spdm_response;

    printf("SPDM_ERROR ");

    if (buffer_size < sizeof(spdm_error_response_t)) {
        printf("\n");
        return;
    }

    spdm_response = buffer;

    if (!m_param_quite_mode) {
        printf("(ErrCode=0x%02x(",
               spdm_response->header.param1);

        dump_entry_value(
            m_spdm_error_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_error_string_table),
            spdm_response->header.param1);

        printf("), ErrData=0x%02x) ",
               spdm_response->header.param2);

        if (spdm_response->header.param1 ==
            SPDM_ERROR_CODE_RESPONSE_NOT_READY) {
            if (buffer_size >=
                sizeof(spdm_error_response_data_response_not_ready_t)) {
                const spdm_error_response_data_response_not_ready_t
                *spdm_responseNotReady;

                spdm_responseNotReady = buffer;
                printf("(ReqCode=0x%02x, Token=0x%02x, RDTExponent=0x%02x, RDTM=0x%02x) ",
                       spdm_responseNotReady->extend_error_data
                       .request_code,
                       spdm_responseNotReady->extend_error_data
                       .token,
                       spdm_responseNotReady->extend_error_data
                       .rd_exponent,
                       spdm_responseNotReady->extend_error_data
                       .rd_tm);
            }
        }
    }

    if (spdm_response->header.param1 == SPDM_ERROR_CODE_DECRYPT_ERROR) {
        libspdm_free_session_id(m_spdm_context, m_current_session_id);
    }

    printf("\n");
}

void dump_spdm_vendor_defined_request(const void *buffer, size_t buffer_size)
{
    const spdm_vendor_defined_request_msg_t *spdm_request;
    size_t header_size;

    printf("SPDM_VENDOR_DEFINED_REQUEST ");

    if (buffer_size < sizeof(spdm_vendor_defined_request_msg_t)) {
        printf("\n");
        return;
    }
    header_size = offsetof(spdm_vendor_defined_request_msg_t, standard_id);

    spdm_request = buffer;

    if (!m_param_quite_mode) {
        printf("(StandID=0x%04x) ", spdm_request->standard_id);
    }

    if (m_param_dump_vendor_app) {
        dump_dispatch_message(m_spdm_vendor_dispatch,
                              LIBSPDM_ARRAY_SIZE(m_spdm_vendor_dispatch),
                              spdm_request->standard_id,
                              (uint8_t *)buffer + header_size,
                              buffer_size - header_size);
    } else {
        printf("\n");
    }
}

void dump_spdm_vendor_defined_response(const void *buffer, size_t buffer_size)
{
    const spdm_vendor_defined_response_msg_t *spdm_response;
    size_t header_size;

    printf("SPDM_VENDOR_DEFINED_RESPONSE ");

    if (buffer_size < sizeof(spdm_vendor_defined_request_msg_t)) {
        printf("\n");
        return;
    }
    header_size = offsetof(spdm_vendor_defined_request_msg_t, standard_id);

    spdm_response = buffer;

    if (!m_param_quite_mode) {
        printf("(StandID=0x%04x) ", spdm_response->standard_id);
    }

    if (m_param_dump_vendor_app) {
        dump_dispatch_message(m_spdm_vendor_dispatch,
                              LIBSPDM_ARRAY_SIZE(m_spdm_vendor_dispatch),
                              spdm_response->standard_id,
                              (uint8_t *)buffer + header_size,
                              buffer_size - header_size);
    } else {
        printf("\n");
    }
}

void dump_spdm_key_exchange(const void *buffer, size_t buffer_size)
{
    const spdm_key_exchange_request_t *spdm_request;
    size_t message_size;
    size_t exchange_data_size;
    uint16_t opaque_length;
    uint8_t *exchange_data;
    uint8_t *opaque_data;

    printf("SPDM_KEY_EXCHANGE ");

    message_size = sizeof(spdm_key_exchange_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;
    if (m_spdm_dhe_named_group != 0) {
        exchange_data_size = libspdm_get_dhe_pub_key_size(m_spdm_dhe_named_group);
    }
    if (m_spdm_kem_alg != 0) {
        exchange_data_size = libspdm_get_kem_encap_key_size(m_spdm_kem_alg);
    }
    message_size += exchange_data_size + sizeof(uint16_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    opaque_length =
        *(uint16_t *)((size_t)buffer +
                      sizeof(spdm_key_exchange_request_t) + exchange_data_size);
    message_size += opaque_length;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    m_cached_measurement_summary_hash_type = spdm_request->header.param1;

    if (!m_param_quite_mode) {
        printf("(HashType=0x%02x(", spdm_request->header.param1);
        dump_entry_value(
            m_spdm_request_hash_type_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_request_hash_type_string_table),
            spdm_request->header.param1);
        printf("), SlotID=0x%02x, ReqSessionID=0x%04x",
               spdm_request->header.param2,
               spdm_request->req_session_id);
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
            printf(", Policy=0x%02x(",
                   spdm_request->session_policy);
            dump_entry_flags(
                m_spdm_key_exchange_session_policy_string_table,
                LIBSPDM_ARRAY_SIZE(m_spdm_key_exchange_session_policy_string_table),
                spdm_request->session_policy);
            printf(")");
        }
        printf(") ");

        if (m_param_all_mode) {
            printf("\n    RandomData(");
            dump_data(spdm_request->random_data, 32);
            printf(")");
            exchange_data = (void *)(spdm_request + 1);
            printf("\n    ExchangeData(");
            dump_data(exchange_data, exchange_data_size);
            printf(")");
            opaque_length = *(uint16_t *)((uint8_t *)exchange_data +
                                          exchange_data_size);
            opaque_data = (void *)((uint8_t *)exchange_data +
                                   exchange_data_size + sizeof(uint16_t));
            printf("\n    OpaqueData(");
            dump_data(opaque_data, opaque_length);
            printf(")");
            dump_spdm_opaque_data(spdm_request->header.spdm_version,
                                  opaque_data, opaque_length);
        }
    }

    printf("\n");

    /*change global m_responder_cert_chain_slot_id when key exchange*/
    if (spdm_request->header.param2 < SPDM_MAX_SLOT_COUNT) {
        m_responder_cert_chain_slot_id = spdm_request->header.param2;
    } else if (spdm_request->header.param2 == 0xFF) {
        /*When key exchange param2 is 0xFF, m_responder_cert_chain_slot_id will be pre-provisioned slot_id.*/
        m_responder_cert_chain_slot_id = SPDM_MAX_SLOT_COUNT;
    } else {
        printf("spdm_request->header.param2 is not right\n");
        return;
    }

    m_cached_session_id = spdm_request->req_session_id;
    memcpy(m_spdm_last_message_buffer, buffer, message_size);
    m_spdm_last_message_buffer_size = message_size;
}

void dump_spdm_key_exchange_rsp(const void *buffer, size_t buffer_size)
{
    const spdm_key_exchange_response_t *spdm_response;
    size_t message_size;
    size_t exchange_data_size;
    size_t measurement_summary_hash_size;
    size_t signature_size;
    size_t hmac_size;
    uint16_t opaque_length;
    bool include_hmac;
    uint8_t *exchange_data;
    uint8_t *measurement_summary_hash;
    uint8_t *opaque_data;
    uint8_t *signature;
    uint8_t *verify_data;
    uint8_t th1_hash_data[64];
    uint8_t mut_auth_requested;

    printf("SPDM_KEY_EXCHANGE_RSP ");

    message_size = sizeof(spdm_key_exchange_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    if (m_spdm_dhe_named_group != 0) {
        exchange_data_size = libspdm_get_dhe_pub_key_size(m_spdm_dhe_named_group);
    }
    if (m_spdm_kem_alg != 0) {
        exchange_data_size = libspdm_get_kem_encap_key_size(m_spdm_kem_alg);
    }
    if (m_spdm_base_asym_algo != 0) {
        signature_size = libspdm_get_asym_signature_size(m_spdm_base_asym_algo);
    }
    if (m_spdm_pqc_asym_algo != 0) {
        signature_size = libspdm_get_pqc_asym_signature_size(m_spdm_pqc_asym_algo);
    }
    measurement_summary_hash_size =
        spdm_dump_get_measurement_summary_hash_size(
            m_cached_measurement_summary_hash_type);
    hmac_size = libspdm_get_hash_size(m_spdm_base_hash_algo);

    message_size +=
        exchange_data_size + measurement_summary_hash_size + sizeof(uint16_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    opaque_length = *(
        uint16_t *)((size_t)buffer + sizeof(spdm_key_exchange_response_t) +
                    exchange_data_size + measurement_summary_hash_size);
    message_size += opaque_length + signature_size;
    include_hmac =
        ((m_spdm_responder_capabilities_flags &
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) ==
         0) ||
        ((m_spdm_requester_capabilities_flags &
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) ==
         0);
    if (include_hmac) {
        message_size += hmac_size;
    }
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(Heart=0x%02x, RspSessionID=0x%04x, MutAuth=0x%02x(",
               spdm_response->header.param1,
               spdm_response->rsp_session_id,
               spdm_response->mut_auth_requested);
        dump_entry_flags(
            m_spdm_key_exchange_mut_auth_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_key_exchange_mut_auth_string_table),
            spdm_response->mut_auth_requested);
        printf("), ReqSlotID=0x%02x) ",
               spdm_response->req_slot_id_param);

        if (m_param_all_mode) {
            printf("\n    RandomData(");
            dump_data(spdm_response->random_data, 32);
            printf(")");
            exchange_data = (void *)(spdm_response + 1);
            printf("\n    ExchangeData(");
            dump_data(exchange_data, exchange_data_size);
            printf(")");
            measurement_summary_hash = exchange_data + exchange_data_size;
            if (measurement_summary_hash_size != 0) {
                printf("\n    MeasurementSummaryHash(");
                dump_data(measurement_summary_hash,
                          measurement_summary_hash_size);
                printf(")");
            }
            opaque_length =
                *(uint16_t *)((uint8_t *)measurement_summary_hash +
                              measurement_summary_hash_size);
            opaque_data =
                (void *)((uint8_t *)measurement_summary_hash +
                         measurement_summary_hash_size +
                         sizeof(uint16_t));
            printf("\n    OpaqueData(");
            dump_data(opaque_data, opaque_length);
            printf(")");
            dump_spdm_opaque_data(spdm_response->header.spdm_version,
                                  opaque_data, opaque_length);
            signature = opaque_data + opaque_length;
            printf("\n    Signature(");
            dump_data(signature, signature_size);
            printf(")");
            if (include_hmac) {
                verify_data = signature + signature_size;
                printf("\n    VerifyData(");
                dump_data(verify_data, hmac_size);
                printf(")");
            }
        }
    }

    printf("\n");

    /*change global m_requester_cert_chain_slot_id when key exchange*/
    if (spdm_response->req_slot_id_param < SPDM_MAX_SLOT_COUNT) {
        m_requester_cert_chain_slot_id = spdm_response->req_slot_id_param;
    } else if (spdm_response->req_slot_id_param == 0xF) {
        /*When spdm_response->req_slot_id_param is 0xF, m_requester_cert_chain_slot_id will be pre-provisioned slot_id.*/
        m_requester_cert_chain_slot_id = SPDM_MAX_SLOT_COUNT;
    } else {
        printf("spdm_response->req_slot_id_param is not right\n");
        return;
    }

    m_cached_session_id = libspdm_generate_session_id((uint16_t)m_cached_session_id,
        spdm_response->rsp_session_id);
    /* double check if current is occupied*/
    if (libspdm_get_session_info_via_session_id(m_spdm_context,
                                                m_cached_session_id) != NULL) {
        /* this might happen if a session is terminated without EndSession*/
        libspdm_free_session_id(m_spdm_context, m_cached_session_id);
    }
    m_current_session_info = libspdm_assign_session_id(
        m_spdm_context, m_cached_session_id, false);
    LIBSPDM_ASSERT(m_current_session_info != NULL);
    if (m_current_session_info == NULL) {
        return;
    }
    m_current_session_id = m_cached_session_id;

    mut_auth_requested = spdm_response->mut_auth_requested;

    spdm_dump_set_session_info_mut_auth_requested (m_current_session_info, mut_auth_requested);

    if (m_spdm_dhe_named_group != 0) {
        if (m_dhe_secret_buffer_count >= LIBSPDM_MAX_SESSION_COUNT) {
            return;
        }
    }
    if (m_spdm_kem_alg != 0) {
        if (m_kem_secret_buffer_count >= LIBSPDM_MAX_SESSION_COUNT) {
            return;
        }
    }

    if (spdm_dump_session_data_provision(m_spdm_context,
                                         m_current_session_id, false,
                                         true) != LIBSPDM_STATUS_SUCCESS) {
        LIBSPDM_DEBUG((LIBSPDM_DEBUG_ERROR,
            "spdm_dump_session_data_provision - failed.\n"));
    }

    hmac_size = libspdm_get_hash_size(m_spdm_base_hash_algo);
    libspdm_append_message_k(m_spdm_context, m_current_session_info, true,
                             m_spdm_last_message_buffer,
                             m_spdm_last_message_buffer_size);
    if (include_hmac) {
        libspdm_append_message_k(m_spdm_context, m_current_session_info, true, buffer,
                                 message_size - hmac_size);
    } else {
        libspdm_append_message_k(m_spdm_context, m_current_session_info, true, buffer,
                                 message_size);
    }

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_handshake_key[%08x]\n",
                   m_current_session_id));

    libspdm_calculate_th1_hash(m_spdm_context, m_current_session_info, true,
                               th1_hash_data);
    libspdm_generate_session_handshake_key(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        th1_hash_data);
    if (include_hmac) {
        libspdm_append_message_k(m_spdm_context,
                                 m_current_session_info, true,
                                 (uint8_t *)buffer + message_size - hmac_size, hmac_size);
    }

    libspdm_secured_message_set_session_state(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        LIBSPDM_SESSION_STATE_HANDSHAKING);
}

void dump_spdm_finish(const void *buffer, size_t buffer_size)
{
    const spdm_finish_request_t *spdm_request;
    size_t message_size;
    size_t signature_size;
    size_t hmac_size;
    bool include_signature;
    uint8_t *signature;
    uint8_t *verify_data;

    printf("SPDM_FINISH ");

    message_size = sizeof(spdm_finish_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;
    if (m_spdm_req_base_asym_alg != 0) {
        signature_size = libspdm_get_req_asym_signature_size(m_spdm_req_base_asym_alg);
    }
    if (m_spdm_req_pqc_asym_alg != 0) {
        signature_size = libspdm_get_req_pqc_asym_signature_size(m_spdm_req_pqc_asym_alg);
    }
    hmac_size = libspdm_get_hash_size(m_spdm_base_hash_algo);

    include_signature =
        ((spdm_request->header.param1 &
          SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED) != 0);
    if (include_signature) {
        message_size += signature_size;
    }
    message_size += hmac_size;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(Attr=0x%02x (SigIncl=%x), ReqSlotID=0x%02x) ",
               spdm_request->header.param1,
               ((spdm_request->header.param1 &
                 SPDM_FINISH_REQUEST_ATTRIBUTES_SIGNATURE_INCLUDED) !=
                0) ?
               1 :
               0,
               spdm_request->header.param2);

        if (m_param_all_mode) {
            if (include_signature) {
                signature = (void *)(spdm_request + 1);
                printf("\n    Signature(");
                dump_data(signature, signature_size);
                printf(")");
                verify_data = signature + signature_size;
            } else {
                verify_data = (void *)(spdm_request + 1);
            }
            printf("\n    VerifyData(");
            dump_data(verify_data, hmac_size);
            printf(")");
        }
    }

    printf("\n");

    LIBSPDM_ASSERT(m_current_session_info != NULL);
    memcpy(m_spdm_last_message_buffer, buffer, message_size);
    m_spdm_last_message_buffer_size = message_size;
}

void dump_spdm_finish_rsp(const void *buffer, size_t buffer_size)
{
    const spdm_finish_response_t *spdm_response;
    size_t message_size;
    size_t hmac_size;
    bool include_hmac;
    uint8_t *verify_data;
    uint8_t th2_hash_data[64];

    printf("SPDM_FINISH_RSP ");

    message_size = sizeof(spdm_finish_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    hmac_size = libspdm_get_hash_size(m_spdm_base_hash_algo);

    include_hmac =
        ((m_spdm_responder_capabilities_flags &
          SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) !=
         0) &&
        ((m_spdm_requester_capabilities_flags &
          SPDM_GET_CAPABILITIES_REQUEST_FLAGS_HANDSHAKE_IN_THE_CLEAR_CAP) !=
         0);
    if (include_hmac) {
        message_size += hmac_size;
    }
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");

        if (m_param_all_mode) {
            if (include_hmac) {
                verify_data = (void *)(spdm_response + 1);
                printf("\n    VerifyData(");
                dump_data(verify_data, hmac_size);
                printf(")");
            }
        }
    }

    printf("\n");

    LIBSPDM_ASSERT(m_current_session_info != NULL);
    if (m_current_session_info == NULL) {
        return;
    }

    if (m_spdm_dhe_named_group != 0) {
        if (m_dhe_secret_buffer_count >= LIBSPDM_MAX_SESSION_COUNT) {
            return;
        }
    }
    if (m_spdm_kem_alg != 0) {
        if (m_kem_secret_buffer_count >= LIBSPDM_MAX_SESSION_COUNT) {
            return;
        }
    }

    if (spdm_dump_session_data_provision(m_spdm_context,
                                         m_current_session_id, true,
                                         true) != LIBSPDM_STATUS_SUCCESS) {
        return;
    }

    libspdm_append_message_f(m_spdm_context, m_current_session_info, true,
                             m_spdm_last_message_buffer,
                             m_spdm_last_message_buffer_size);
    libspdm_append_message_f(m_spdm_context, m_current_session_info, true, buffer, message_size);

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_data_key[%08x]\n",
                   m_current_session_id));

    if (spdm_dump_session_data_check(m_spdm_context, m_current_session_id,
                                     true) != LIBSPDM_STATUS_SUCCESS) {
        return;
    }
    libspdm_calculate_th2_hash(m_spdm_context, m_current_session_info, true,
                               th2_hash_data);
    libspdm_generate_session_data_key(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        th2_hash_data);
    /*use next key when next seesion start*/
    if (m_spdm_dhe_named_group != 0) {
        m_dhe_secret_buffer_count++;
    }
    if (m_spdm_kem_alg != 0) {
        m_kem_secret_buffer_count++;
    }

    libspdm_secured_message_set_session_state(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
}

void dump_spdm_psk_exchange(const void *buffer, size_t buffer_size)
{
    const spdm_psk_exchange_request_t *spdm_request;
    size_t message_size;
    uint8_t *psk_hint;
    uint8_t *context;
    uint8_t *opaque_data;

    printf("SPDM_PSK_EXCHANGE ");

    message_size = sizeof(spdm_psk_exchange_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;
    message_size += spdm_request->psk_hint_length +
                    spdm_request->context_length +
                    spdm_request->opaque_length;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    m_cached_measurement_summary_hash_type = spdm_request->header.param1;

    if (!m_param_quite_mode) {
        printf("(HashType=0x%02x(", spdm_request->header.param1);
        dump_entry_value(
            m_spdm_request_hash_type_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_request_hash_type_string_table),
            spdm_request->header.param1);
        printf("), ReqSessionID=0x%04x",
               spdm_request->req_session_id);
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
            printf(", Policy=0x%02x(",
                   spdm_request->header.param2);
            dump_entry_flags(
                m_spdm_key_exchange_session_policy_string_table,
                LIBSPDM_ARRAY_SIZE(m_spdm_key_exchange_session_policy_string_table),
                spdm_request->header.param2);
            printf(")");
        }
        printf(", PSKHint=");
        psk_hint = (void *)(spdm_request + 1);
        dump_hex_str(psk_hint, spdm_request->psk_hint_length);
        printf(") ");

        if (m_param_all_mode) {
            context = psk_hint + spdm_request->psk_hint_length;
            printf("\n    Context(");
            dump_data(context, spdm_request->context_length);
            printf(")");
            opaque_data = context + spdm_request->context_length;
            printf("\n    OpaqueData(");
            dump_data(opaque_data, spdm_request->opaque_length);
            printf(")");
            dump_spdm_opaque_data(spdm_request->header.spdm_version,
                                  opaque_data, spdm_request->opaque_length);
        }
    }

    printf("\n");

    m_cached_session_id = spdm_request->req_session_id;
    memcpy(m_spdm_last_message_buffer, buffer, message_size);
    m_spdm_last_message_buffer_size = message_size;
}

void dump_spdm_psk_exchange_rsp(const void *buffer, size_t buffer_size)
{
    const spdm_psk_exchange_response_t *spdm_response;
    size_t message_size;
    size_t measurement_summary_hash_size;
    size_t hmac_size;
    uint8_t *measurement_summary_hash;
    uint8_t *context;
    uint8_t *opaque_data;
    uint8_t *verify_data;
    uint8_t th1_hash_data[64];
    uint8_t th2_hash_data[64];

    printf("SPDM_PSK_EXCHANGE_RSP ");

    message_size = sizeof(spdm_psk_exchange_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    measurement_summary_hash_size =
        spdm_dump_get_measurement_summary_hash_size(
            m_cached_measurement_summary_hash_type);
    hmac_size = libspdm_get_hash_size(m_spdm_base_hash_algo);
    message_size += measurement_summary_hash_size +
                    spdm_response->context_length +
                    spdm_response->opaque_length + hmac_size;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(Heart=0x%02x, RspSessionID=0x%04x) ",
               spdm_response->header.param1,
               spdm_response->rsp_session_id);

        if (m_param_all_mode) {
            measurement_summary_hash = (void *)(spdm_response + 1);
            if (measurement_summary_hash_size != 0) {
                printf("\n    MeasurementSummaryHash(");
                dump_data(measurement_summary_hash,
                          measurement_summary_hash_size);
                printf(")");
            }
            context = measurement_summary_hash +
                      measurement_summary_hash_size;
            printf("\n    Context(");
            dump_data(context, spdm_response->context_length);
            printf(")");
            opaque_data = context + spdm_response->context_length;
            printf("\n    OpaqueData(");
            dump_data(opaque_data, spdm_response->opaque_length);
            printf(")");
            dump_spdm_opaque_data(spdm_response->header.spdm_version,
                                  opaque_data, spdm_response->opaque_length);
            verify_data =
                opaque_data + spdm_response->opaque_length;
            printf("\n    VerifyData(");
            dump_data(verify_data, hmac_size);
            printf(")");
        }
    }

    printf("\n");

    m_cached_session_id = libspdm_generate_session_id((uint16_t)m_cached_session_id,
        spdm_response->rsp_session_id);
    /* double check if current is occupied*/
    if (libspdm_get_session_info_via_session_id(m_spdm_context,
                                                m_cached_session_id) != NULL) {
        /* this might happen if a session is terminated without EndSession*/
        libspdm_free_session_id(m_spdm_context, m_cached_session_id);
    }
    m_current_session_info = libspdm_assign_session_id(
        m_spdm_context, m_cached_session_id, true);
    LIBSPDM_ASSERT(m_current_session_info != NULL);
    if (m_current_session_info == NULL) {
        return;
    }
    m_current_session_id = m_cached_session_id;

    if (m_psk_secret_buffer_count >= LIBSPDM_MAX_SESSION_COUNT) {
        return;
    }
    if (spdm_dump_session_data_provision(m_spdm_context,
                                         m_current_session_id, false,
                                         true) != LIBSPDM_STATUS_SUCCESS) {
        return;
    }

    libspdm_append_message_k(m_spdm_context, m_current_session_info, true,
                             m_spdm_last_message_buffer,
                             m_spdm_last_message_buffer_size);
    libspdm_append_message_k(m_spdm_context, m_current_session_info, true, buffer,
                             message_size - hmac_size);

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_handshake_key[%08x]\n",
                   m_current_session_id));

    libspdm_calculate_th1_hash(m_spdm_context, m_current_session_info, true,
                               th1_hash_data);

    libspdm_generate_session_handshake_key(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        th1_hash_data);

    libspdm_append_message_k(m_spdm_context, m_current_session_info, true,
                             (uint8_t *)buffer + message_size - hmac_size,
                             hmac_size);

    libspdm_secured_message_set_session_state(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        LIBSPDM_SESSION_STATE_HANDSHAKING);

    if ((m_spdm_responder_capabilities_flags &
         SPDM_GET_CAPABILITIES_RESPONSE_FLAGS_PSK_CAP_RESPONDER_WITH_CONTEXT) ==
        0) {
        /* No need to receive PSK_FINISH, enter application phase directly.*/

        libspdm_calculate_th2_hash(m_spdm_context, m_current_session_info,
                                   true, th2_hash_data);

        libspdm_generate_session_data_key(
            libspdm_get_secured_message_context_via_session_info(
                m_current_session_info),
            th2_hash_data);

        libspdm_secured_message_set_session_state(
            libspdm_get_secured_message_context_via_session_info(
                m_current_session_info),
            LIBSPDM_SESSION_STATE_ESTABLISHED);
    }
}

void dump_spdm_psk_finish(const void *buffer, size_t buffer_size)
{
    const spdm_psk_finish_request_t *spdm_request;
    size_t message_size;
    size_t hmac_size;
    uint8_t *verify_data;

    printf("SPDM_PSK_FINISH ");

    message_size = sizeof(spdm_psk_finish_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;
    hmac_size = libspdm_get_hash_size(m_spdm_base_hash_algo);
    message_size += hmac_size;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");

        if (m_param_all_mode) {
            verify_data = (void *)(spdm_request + 1);
            printf("\n    VerifyData(");
            dump_data(verify_data, hmac_size);
            printf(")");
        }
    }

    printf("\n");

    LIBSPDM_ASSERT(m_current_session_info != NULL);
    if (m_current_session_info == NULL) {
        return;
    }
    libspdm_append_message_f(m_spdm_context, m_current_session_info, true, buffer, message_size);
}

void dump_spdm_psk_finish_rsp(const void *buffer, size_t buffer_size)
{
    size_t message_size;
    uint8_t th2_hash_data[64];

    printf("SPDM_PSK_FINISH_RSP ");

    message_size = sizeof(spdm_psk_finish_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");

    LIBSPDM_ASSERT(m_current_session_info != NULL);
    if (m_current_session_info == NULL) {
        return;
    }

    if (m_psk_secret_buffer_count >= LIBSPDM_MAX_SESSION_COUNT) {
        return;
    }
    if (spdm_dump_session_data_provision(m_spdm_context,
                                         m_current_session_id, true,
                                         true) != LIBSPDM_STATUS_SUCCESS) {
        return;
    }

    libspdm_append_message_f(m_spdm_context, m_current_session_info, true, buffer, message_size);

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_data_key[%08x]\n",
                   m_current_session_id));

    if (spdm_dump_session_data_check(m_spdm_context, m_current_session_id,
                                     true) != LIBSPDM_STATUS_SUCCESS) {
        return;
    }
    libspdm_calculate_th2_hash(m_spdm_context, m_current_session_info, true,
                               th2_hash_data);

    libspdm_generate_session_data_key(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        th2_hash_data);

    /*use next key when next seesion start*/
    m_psk_secret_buffer_count++;

    libspdm_secured_message_set_session_state(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        LIBSPDM_SESSION_STATE_ESTABLISHED);
}

void dump_spdm_heartbeat(const void *buffer, size_t buffer_size)
{
    printf("SPDM_HEARTBEAT ");

    if (buffer_size < sizeof(spdm_heartbeat_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_heartbeat_ack(const void *buffer, size_t buffer_size)
{
    printf("SPDM_HEARTBEAT_ACK ");

    if (buffer_size < sizeof(spdm_heartbeat_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_key_update(const void *buffer, size_t buffer_size)
{
    const spdm_key_update_request_t *spdm_request;

    printf("SPDM_KEY_UPDATE ");

    if (buffer_size < sizeof(spdm_key_update_request_t)) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (!m_param_quite_mode) {
        printf("(KeyOp=0x%02x(", spdm_request->header.param1);
        dump_entry_value(
            m_spdm_key_update_operation_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_key_update_operation_string_table),
            spdm_request->header.param1);
        printf("), Tag=0x%02x) ", spdm_request->header.param2);
    }

    printf("\n");

    LIBSPDM_ASSERT(m_current_session_info != NULL);
    if (m_encapsulated) {
        LIBSPDM_ASSERT(m_current_session_info != NULL);
        switch (((spdm_message_header_t *)buffer)->param1) {
        case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
            libspdm_create_update_session_data_key(
                libspdm_get_secured_message_context_via_session_info(
                    m_current_session_info),
                LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);
            break;
        }
    } else {
        switch (((spdm_message_header_t *)buffer)->param1) {
        case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_KEY:
            libspdm_create_update_session_data_key(
                libspdm_get_secured_message_context_via_session_info(
                    m_current_session_info),
                LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
            break;
        case SPDM_KEY_UPDATE_OPERATIONS_TABLE_UPDATE_ALL_KEYS:
            libspdm_create_update_session_data_key(
                libspdm_get_secured_message_context_via_session_info(
                    m_current_session_info),
                LIBSPDM_KEY_UPDATE_ACTION_REQUESTER);
            libspdm_create_update_session_data_key(
                libspdm_get_secured_message_context_via_session_info(
                    m_current_session_info),
                LIBSPDM_KEY_UPDATE_ACTION_RESPONDER);
            break;
        }
    }
}

void dump_spdm_key_update_ack(const void *buffer, size_t buffer_size)
{
    const spdm_key_update_response_t *spdm_response;

    printf("SPDM_KEY_UPDATE_ACK ");

    if (buffer_size < sizeof(spdm_key_update_response_t)) {
        printf("\n");
        return;
    }

    spdm_response = buffer;

    if (!m_param_quite_mode) {
        printf("(KeyOp=0x%02x(", spdm_response->header.param1);
        dump_entry_value(
            m_spdm_key_update_operation_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_key_update_operation_string_table),
            spdm_response->header.param1);
        printf("), Tag=0x%02x) ", spdm_response->header.param2);
    }

    printf("\n");
}

void dump_spdm_get_encapsulated_request(const void *buffer, size_t buffer_size)
{
    printf("SPDM_GET_ENCAPSULATED_REQUEST ");

    if (buffer_size < sizeof(spdm_get_encapsulated_request_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_encapsulated_request(const void *buffer, size_t buffer_size)
{
    const spdm_encapsulated_request_response_t *spdm_response;
    size_t header_size;

    printf("SPDM_ENCAPSULATED_REQUEST ");

    header_size = sizeof(spdm_encapsulated_request_response_t);
    if (buffer_size < header_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    if (!m_param_quite_mode) {
        printf("(ReqID=0x%02x) ", spdm_response->header.param1);
    }

    m_encapsulated = true;
    dump_spdm_message((uint8_t *)buffer + header_size,
                      buffer_size - header_size);
    m_encapsulated = false;
}

void dump_spdm_deliver_encapsulated_response(const void *buffer,
                                             size_t buffer_size)
{
    const spdm_deliver_encapsulated_response_request_t *spdm_request;
    size_t header_size;

    printf("SPDM_DELIVER_ENCAPSULATED_RESPONSE ");

    header_size = sizeof(spdm_deliver_encapsulated_response_request_t);
    if (buffer_size < header_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;
    if (!m_param_quite_mode) {
        printf("(ReqID=0x%02x) ", spdm_request->header.param1);
    }

    m_encapsulated = true;
    dump_spdm_message((uint8_t *)buffer + header_size,
                      buffer_size - header_size);
    m_encapsulated = false;
}

void dump_spdm_encapsulated_response_ack(const void *buffer, size_t buffer_size)
{
    const spdm_encapsulated_response_ack_response_t *spdm_response;
    size_t header_size;
    uint8_t req_slot_id;

    printf("SPDM_ENCAPSULATED_RESPONSE_ACK ");

    header_size = sizeof(spdm_message_header_t);
    if (buffer_size < header_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        header_size = sizeof(spdm_encapsulated_response_ack_response_t);
    }

    if (!m_param_quite_mode) {
        printf("(ReqID=0x%02x", spdm_response->header.param1);
        if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
            printf(", AckReqID=0x%02x", spdm_response->ack_request_id);
        }
        printf(") ");
    }

    switch (spdm_response->header.param2) {
    case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_ABSENT:
        if (!m_param_quite_mode) {
            printf("(Done) ");
        }
        break;

    case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_PRESENT:
        m_encapsulated = true;
        dump_spdm_message((uint8_t *)buffer + header_size,
                          buffer_size - header_size);
        m_encapsulated = false;
        return;

    case SPDM_ENCAPSULATED_RESPONSE_ACK_RESPONSE_PAYLOAD_TYPE_REQ_SLOT_NUMBER:
        if (buffer_size < header_size + 1) {
            printf("\n");
            return;
        }

        req_slot_id = *((uint8_t *)buffer + header_size);
        if (!m_param_quite_mode) {
            printf("(ReqSlotID=0x%02x) ", req_slot_id);
        }

        /*change global m_requester_cert_chain_slot_id when encapsulated_response_ack*/
        if (req_slot_id < SPDM_MAX_SLOT_COUNT) {
            m_requester_cert_chain_slot_id = req_slot_id;
        } else {
            printf("ReqSlotID is not right\n");
            return;
        }

        break;
    }
    printf("\n");
}

void dump_spdm_end_session(const void *buffer, size_t buffer_size)
{
    const spdm_end_session_request_t *spdm_request;

    printf("SPDM_END_SESSION ");

    if (buffer_size < sizeof(spdm_end_session_request_t)) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (!m_param_quite_mode) {
        printf("(Attr=0x%02x(", spdm_request->header.param1);
        dump_entry_flags(
            m_spdm_end_session_attribute_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_end_session_attribute_string_table),
            spdm_request->header.param1);
        printf(")) ");
    }

    printf("\n");
}

void dump_spdm_end_session_ack(const void *buffer, size_t buffer_size)
{
    printf("SPDM_END_SESSION_ACK ");

    if (buffer_size < sizeof(spdm_end_session_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    libspdm_free_session_id(m_spdm_context, m_current_session_id);

    printf("\n");
}

void dump_spdm_get_csr(const void *buffer, size_t buffer_size)
{
    const spdm_get_csr_request_t *spdm_request;
    uint8_t *ptr;

    printf("SPDM_GET_CSR ");

    if (buffer_size < sizeof(spdm_get_csr_request_t)) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (buffer_size < sizeof(spdm_get_csr_request_t) +
                      spdm_request->opaque_data_length +
                      spdm_request->requester_info_length) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(");
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            printf("KeyPairID=0x%02x", spdm_request->header.param1);
            printf(", Attr=0x%02x(", spdm_request->header.param2);
            dump_entry_value(
                m_spdm_cert_model_string_table,
                LIBSPDM_ARRAY_SIZE(m_spdm_cert_model_string_table),
                spdm_request->header.param2 &
                SPDM_GET_CSR_REQUEST_ATTRIBUTES_CERT_MODEL_MASK);
            printf(", Tag=0x%02x",
                (spdm_request->header.param2  &
                 SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_MASK) >>
                SPDM_GET_CSR_REQUEST_ATTRIBUTES_CSR_TRACKING_TAG_OFFSET);
            printf(", Overwrite=%02x",
                (spdm_request->header.param2 &
                 SPDM_GET_CSR_REQUEST_ATTRIBUTES_OVERWRITE) >> 7);
            printf(")");
        }
        printf(") ");
        if (m_param_all_mode) {
            printf("\n    RequesterInfo(");
            ptr = (void *)(spdm_request + 1);
            dump_data(ptr, spdm_request->requester_info_length);
            printf(")");

            printf("\n    OpaqueData(");
            ptr = (void *)(ptr + spdm_request->requester_info_length);
            dump_data(ptr, spdm_request->opaque_data_length);
            printf(")");
        }
    }

    printf("\n");
}

void dump_spdm_csr(const void *buffer, size_t buffer_size)
{
    const spdm_csr_response_t *spdm_response;
    uint8_t *ptr;

    printf("SPDM_CSR ");

    if (buffer_size < sizeof(spdm_csr_response_t)) {
        printf("\n");
        return;
    }

    spdm_response = buffer;

    if (buffer_size < sizeof(spdm_csr_response_t) +
                      spdm_response->csr_length) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
        if (m_param_all_mode) {
            printf("\n    CSR(");
            ptr = (void *)(spdm_response + 1);
            dump_data(ptr, spdm_response->csr_length);
            printf(")");
        }
    }

    printf("\n");
}

void dump_spdm_set_certificate(const void *buffer, size_t buffer_size)
{
    const spdm_set_certificate_request_t *spdm_request;
    const spdm_cert_chain_t *cert_chain;

    printf("SPDM_SET_CERTIFICATE ");

    if (buffer_size < sizeof(spdm_set_certificate_request_t) + sizeof(spdm_cert_chain_t)) {
        printf("\n");
        return;
    }

    spdm_request = buffer;
    cert_chain = (void *)(spdm_request + 1);
    if (buffer_size < sizeof(spdm_set_certificate_request_t) + cert_chain->length) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(Attr=0x%02x(", spdm_request->header.param1);
        printf("SlotID=0x%02x", spdm_request->header.param1 & 0xF);
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            printf(", ");
            dump_entry_value(
                m_spdm_cert_model_string_table,
                LIBSPDM_ARRAY_SIZE(m_spdm_cert_model_string_table),
                (spdm_request->header.param1 &
                 SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_CERT_MODEL_MASK) >>
                SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_CERT_MODEL_OFFSET);
            printf(", Erase=%02x",
                (spdm_request->header.param1 &
                 SPDM_SET_CERTIFICATE_REQUEST_ATTRIBUTES_ERASE) >> 7);
        }
        printf(")");
        if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_13) {
            printf(", KeyPairID=0x%02x", spdm_request->header.param2);
        }
        printf(")");
        if (m_param_all_mode) {
                printf("\n    CertChain(\n");
                dump_hex((void *)cert_chain, cert_chain->length);
                printf("    )");
        }
    }

    printf("\n");
}

void dump_spdm_set_certificate_rsp(const void *buffer, size_t buffer_size)
{
    const spdm_set_certificate_response_t *spdm_response;

    printf("SPDM_SET_CERTIFICATE_RSP ");

    if (buffer_size < sizeof(spdm_set_certificate_response_t)) {
        printf("\n");
        return;
    }

    spdm_response = buffer;

    if (!m_param_quite_mode) {
        printf("(SlotID=0x%02x) ", spdm_response->header.param1 & 0xF);
    }

    printf("\n");
}

void dump_spdm_get_key_pair_info(const void *buffer, size_t buffer_size)
{
    const spdm_get_key_pair_info_request_t *spdm_request;

    printf("SPDM_GET_KEY_PAIR_INFO ");

    if (buffer_size < sizeof(spdm_get_key_pair_info_request_t)) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (!m_param_quite_mode) {
        printf("(KeyPairID=0x%02x) ", spdm_request->key_pair_id);
    }

    printf("\n");
}

void dump_spdm_key_pair_info(const void *buffer, size_t buffer_size)
{
    const spdm_key_pair_info_response_t *spdm_response;

    printf("SPDM_KEY_PAIR_INFO ");

    if (buffer_size < sizeof(spdm_key_pair_info_response_t)) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    if (buffer_size < sizeof(spdm_key_pair_info_response_t) + spdm_response->public_key_info_len) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(TotalKeyPairs=0x%02x", spdm_response->total_key_pairs);
        printf(", KeyPairID=0x%02x", spdm_response->key_pair_id);
        printf(", Cap=0x%04x(", spdm_response->capabilities);
        dump_entry_flags(
            m_spdm_key_pair_capability_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_key_pair_capability_string_table),
            spdm_response->capabilities);
        printf("), KeyUsageCap=0x%04x(", spdm_response->key_usage_capabilities);
        dump_entry_flags(
            m_spdm_key_usage_value_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_key_usage_value_string_table),
            spdm_response->key_usage_capabilities);
        printf("), CurrKeyUsage=0x%04x(", spdm_response->current_key_usage);
        dump_entry_flags(
            m_spdm_key_usage_value_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_key_usage_value_string_table),
            spdm_response->current_key_usage);
        printf("), AsymCap=0x%08x(", spdm_response->asym_algo_capabilities);
        dump_entry_flags(
            m_spdm_key_pair_asym_algo_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_key_pair_asym_algo_string_table),
            spdm_response->asym_algo_capabilities);
        printf("), CurrAsym=0x%08x(", spdm_response->current_asym_algo);
        dump_entry_flags(
            m_spdm_key_pair_asym_algo_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_key_pair_asym_algo_string_table),
            spdm_response->current_asym_algo);
        printf("), AssicSlotMask=0x%02x", spdm_response->assoc_cert_slot_mask);
        printf(", PubKeyInfo(Len=0x%04x, ", spdm_response->public_key_info_len);
        dump_data((const void *)(spdm_response + 1), spdm_response->public_key_info_len);
        printf("))");
    }

    printf("\n");
}

void dump_spdm_set_key_pair_info(const void *buffer, size_t buffer_size)
{
    const spdm_set_key_pair_info_request_t *spdm_request;
    uint16_t desired_key_usage;
    uint32_t desired_asym_algo;
    uint8_t desired_assoc_cert_slot_mask;
    const uint8_t *ptr;

    printf("SPDM_SET_KEY_PAIR_INFO ");

    if (buffer_size < sizeof(spdm_set_key_pair_info_request_t)) {
        printf("\n");
        return;
    }

    spdm_request = buffer;
    if (spdm_request->header.param1 > SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION) {
        printf("\n");
        return;
    }
    if ((spdm_request->header.param1 != SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION) &&
        (buffer_size < sizeof(spdm_set_key_pair_info_request_t) +
                              sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint32_t) +
                              sizeof(uint8_t))) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(Operation=0x%02x(", spdm_request->header.param1);
        dump_entry_value(
            m_spdm_set_key_pair_info_operation_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_set_key_pair_info_operation_string_table),
            spdm_request->header.param1);
        printf("), KeyPairID=0x%02x", spdm_request->key_pair_id);
        switch(spdm_request->header.param1) {
        case SPDM_SET_KEY_PAIR_INFO_ERASE_OPERATION:
            printf(")");
            break;
        case SPDM_SET_KEY_PAIR_INFO_CHANGE_OPERATION:
        case SPDM_SET_KEY_PAIR_INFO_GENERATE_OPERATION:
            ptr = (const void *)(spdm_request + 1);
            ptr += sizeof(uint8_t);
            desired_key_usage = libspdm_read_uint16(ptr);
            ptr += sizeof(uint16_t);
            desired_asym_algo = libspdm_read_uint32(ptr);
            ptr += sizeof(uint32_t);
            desired_assoc_cert_slot_mask = *ptr;
            ptr += sizeof(uint8_t);
            printf(", DesiredKeyUsage=0x%04x(", desired_key_usage);
            dump_entry_flags(
                m_spdm_key_usage_value_string_table,
                LIBSPDM_ARRAY_SIZE(m_spdm_key_usage_value_string_table),
                desired_key_usage);
            printf("), DesiredAsymAlgo=0x%08x(", desired_asym_algo);
            dump_entry_flags(
                m_spdm_key_pair_asym_algo_string_table,
                LIBSPDM_ARRAY_SIZE(m_spdm_key_pair_asym_algo_string_table),
                desired_asym_algo);
            printf("), DesiredAssocCertSlotMask=0x%02x", desired_assoc_cert_slot_mask);
            printf(")");
            break;
        default:
            printf("\n");
            return ;
        }
    }

    printf("\n");
}

void dump_spdm_set_key_pair_info_ack(const void *buffer, size_t buffer_size)
{
    printf("SPDM_SET_KEY_PAIR_INFO_ACK ");

    if (buffer_size < sizeof(spdm_set_key_pair_info_ack_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_chunk_send(const void *buffer, size_t buffer_size)
{
    const spdm_chunk_send_request_t *spdm_request;
    uint32_t *large_message_size_ptr;
    /*current chunk data*/
    uint8_t *ptr;
    /*pointer to store chunk large message*/
    static uint8_t *chunk_send_large_message_buf = NULL;
    /*loop to store chunk data to large meesage*/
    static uint32_t chunk_send_large_message_current_size;
    /*store the total message_size*/
    static uint32_t chunk_send_large_message_buf_size;

    printf("SPDM_CHUNK_SEND ");

    if (buffer_size < sizeof(spdm_chunk_send_request_t)) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (buffer_size - sizeof(spdm_chunk_send_request_t) < spdm_request->chunk_size) {
        printf("\n");
        return;
    }
    if (spdm_request->chunk_seq_no == 0) {
        if (buffer_size - sizeof(spdm_chunk_send_request_t) - spdm_request->chunk_size <
            sizeof(uint32_t)) {
            printf("\n");
            return;
        }
    }

    if (!m_param_quite_mode) {
        printf("(Attr=0x%02x(", spdm_request->header.param1);
        dump_entry_flags(
            m_spdm_chunk_send_attribute_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_chunk_send_attribute_string_table),
            spdm_request->header.param1);
        printf("), Handle=0x%02x, ChunkSeqNo=0x%04x, ChunkSize=0x%08x",
               spdm_request->header.param2,
               spdm_request->chunk_seq_no,
               spdm_request->chunk_size);
    }

    if (spdm_request->chunk_seq_no == 0) {
        /*first chunk*/
        large_message_size_ptr = (void *)(spdm_request + 1);
        if (!m_param_quite_mode) {
            printf(", LargeMsgSize=0x%08x", *large_message_size_ptr);
        }
        if (chunk_send_large_message_buf != NULL) {
            free(chunk_send_large_message_buf);
            chunk_send_large_message_buf = NULL;
        }
        chunk_send_large_message_buf = malloc(*large_message_size_ptr);
        if (chunk_send_large_message_buf == NULL) {
            printf("!!!memory out of resources!!!\n");
            return;
        }
        chunk_send_large_message_buf_size = *large_message_size_ptr;
        chunk_send_large_message_current_size = 0;
        /*point to SPDMchunk data*/
        ptr = (uint8_t *)(spdm_request + 1) + sizeof(uint32_t);
    } else {
        /*point to SPDMchunk data*/
        ptr = (void *)(spdm_request + 1);
    }

    if (!m_param_quite_mode) {
        printf(") ");
    }

    if (chunk_send_large_message_current_size + spdm_request->chunk_size <=
        chunk_send_large_message_buf_size) {
        /*store chunk data to large message*/
        memcpy(chunk_send_large_message_buf + chunk_send_large_message_current_size,
               ptr, spdm_request->chunk_size);
    } else {
        free(chunk_send_large_message_buf);
        chunk_send_large_message_buf = NULL;
        printf("\n");
        return;
    }

    /*move to store next chunk*/
    chunk_send_large_message_current_size += spdm_request->chunk_size;

    m_chunk_send_lask_chunk_flag = false;
    /*last chunk: dump total large message and free chunk_send_large_message_buf*/
    if (spdm_request->header.param1 == SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK) {

        /*change the last chunk flag*/
        m_chunk_send_lask_chunk_flag = true;

        /*final total chunk size shall equal the LargeMessageSize*/
        if (chunk_send_large_message_current_size != chunk_send_large_message_buf_size) {
            free(chunk_send_large_message_buf);
            chunk_send_large_message_buf = NULL;
            printf("\n");
            return;
        }

        m_chunk_large_message = true;
        dump_spdm_message(chunk_send_large_message_buf, chunk_send_large_message_buf_size);
        m_chunk_large_message = false;

        chunk_send_large_message_current_size = 0;
        chunk_send_large_message_buf_size = 0;
        free(chunk_send_large_message_buf);
        chunk_send_large_message_buf = NULL;
    } else {
        printf("\n");
    }
}

void dump_spdm_chunk_send_ack(const void *buffer, size_t buffer_size)
{
    const spdm_chunk_send_ack_response_t *spdm_response;
    size_t header_size;

    header_size = sizeof(spdm_chunk_send_ack_response_t);

    printf("SPDM_CHUNK_SEND_ACK ");

    if (buffer_size < sizeof(spdm_chunk_send_ack_response_t)) {
        printf("\n");
        return;
    }

    spdm_response = buffer;

    if (!m_param_quite_mode) {
        printf("(Attr=0x%02x(", spdm_response->header.param1);
        dump_entry_flags(
            m_spdm_chunk_send_ack_attribute_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_chunk_send_ack_attribute_string_table),
            spdm_response->header.param1);
        printf("), Handle=0x%02x, ChunkSeqNo=0x%04x) ",
               spdm_response->header.param2,
               spdm_response->chunk_seq_no);
    }

    if (m_chunk_send_lask_chunk_flag) {

        m_chunk_large_message = true;
        dump_spdm_message((uint8_t *)buffer + header_size,
                          buffer_size - header_size);
        m_chunk_large_message = false;

        m_chunk_send_lask_chunk_flag = false;
    } else {
        printf("\n");
    }

}

void dump_spdm_chunk_get(const void *buffer, size_t buffer_size)
{
    const spdm_chunk_get_request_t *spdm_request;

    printf("SPDM_CHUNK_GET ");

    if (buffer_size < sizeof(spdm_chunk_get_request_t)) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (!m_param_quite_mode) {
        printf("(Handle=0x%02x, ChunkSeqNo=0x%04x) ",
               spdm_request->header.param2,
               spdm_request->chunk_seq_no);
    }

    printf("\n");
}

void dump_spdm_chunk_response(const void *buffer, size_t buffer_size)
{
    const spdm_chunk_response_response_t *spdm_response;
    uint32_t *large_message_size_ptr;
    /*current chunk data*/
    uint8_t *ptr;
    /*pointer to store chunk large message*/
    static uint8_t *chunk_response_large_message_buf = NULL;
    /*loop to store chunk data to large meesage*/
    static uint32_t chunk_response_large_message_current_size;
    /*store the total message_size*/
    static uint32_t chunk_response_large_message_buf_size = 0;

    printf("SPDM_CHUNK_RESPONSE ");

    if (buffer_size < sizeof(spdm_chunk_response_response_t)) {
        printf("\n");
        return;
    }

    spdm_response = buffer;

    if (buffer_size - sizeof(spdm_chunk_response_response_t) < spdm_response->chunk_size) {
        printf("\n");
        return;
    }
    if (spdm_response->chunk_seq_no == 0) {
        if (buffer_size - sizeof(spdm_chunk_response_response_t) - spdm_response->chunk_size <
            sizeof(uint32_t)) {
            printf("\n");
            return;
        }
    }

    if (!m_param_quite_mode) {
        printf("(Attr=0x%02x(", spdm_response->header.param1);
        dump_entry_flags(
            m_spdm_chunk_send_attribute_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_chunk_send_attribute_string_table),
            spdm_response->header.param1);
        printf("), Handle=0x%02x, ChunkSeqNo=0x%04x, ChunkSize=0x%08x",
               spdm_response->header.param2,
               spdm_response->chunk_seq_no,
               spdm_response->chunk_size);
    }

    if (spdm_response->chunk_seq_no == 0) {
        /*first chunk*/
        large_message_size_ptr = (void *)(spdm_response + 1);
        if (!m_param_quite_mode) {
            printf(", LargeMsgSize=0x%08x", *large_message_size_ptr);
        }
        if (chunk_response_large_message_buf != NULL) {
            free(chunk_response_large_message_buf);
            chunk_response_large_message_buf = NULL;
        }
        chunk_response_large_message_buf = malloc(*large_message_size_ptr);
        if (chunk_response_large_message_buf == NULL) {
            printf("!!!memory out of resources!!!\n");
            return;
        }
        chunk_response_large_message_buf_size = *large_message_size_ptr;
        chunk_response_large_message_current_size = 0;
        /*point to SPDMchunk data*/
        ptr = (uint8_t *)(spdm_response + 1) + sizeof(uint32_t);
    } else {
        /*point to SPDMchunk data*/
        ptr = (void *)(spdm_response + 1);
    }

    if (!m_param_quite_mode) {
        printf(") ");
    }

    if (chunk_response_large_message_current_size + spdm_response->chunk_size <=
        chunk_response_large_message_buf_size) {
        /*store chunk data to large message*/
        memcpy(chunk_response_large_message_buf + chunk_response_large_message_current_size,
            ptr, spdm_response->chunk_size);
    } else {
        free(chunk_response_large_message_buf);
        chunk_response_large_message_buf = NULL;
        printf("\n");
        return;
    }

    /*move to store next chunk*/
    chunk_response_large_message_current_size += spdm_response->chunk_size;

    /*last chunk: dump total large message and free chunk_send_large_message_buf*/
    if (spdm_response->header.param1 == SPDM_CHUNK_SEND_REQUEST_ATTRIBUTE_LAST_CHUNK) {

        /*final total chunk size shall equal the LargeMessageSize*/
        if (chunk_response_large_message_current_size != chunk_response_large_message_buf_size) {
            free(chunk_response_large_message_buf);
            chunk_response_large_message_buf = NULL;
            printf("\n");
            return;
        }

        m_chunk_large_message = true;
        dump_spdm_message(chunk_response_large_message_buf, chunk_response_large_message_buf_size);
        m_chunk_large_message = false;

        chunk_response_large_message_buf_size = 0;
        chunk_response_large_message_current_size = 0;
        free(chunk_response_large_message_buf);
        chunk_response_large_message_buf = NULL;
    } else {
        printf("\n");
    }
}

dispatch_table_entry_t m_spdm_dispatch[] = {
    { SPDM_DIGESTS, "SPDM_DIGESTS", dump_spdm_digests },
    { SPDM_CERTIFICATE, "SPDM_CERTIFICATE", dump_spdm_certificate },
    { SPDM_CHALLENGE_AUTH, "SPDM_CHALLENGE_AUTH",
      dump_spdm_challenge_auth },
    { SPDM_VERSION, "SPDM_VERSION", dump_spdm_version },
    { SPDM_MEASUREMENTS, "SPDM_MEASUREMENTS", dump_spdm_measurements },
    { SPDM_MEASUREMENT_EXTENSION_LOG, "SPDM_MEASUREMENT_EXTENSION_LOG", dump_spdm_mel },
    { SPDM_CAPABILITIES, "SPDM_CAPABILITIES", dump_spdm_capabilities },
    { SPDM_ALGORITHMS, "SPDM_ALGORITHMS", dump_spdm_algorithms },
    { SPDM_VENDOR_DEFINED_RESPONSE, "SPDM_VENDOR_DEFINED_RESPONSE",
      dump_spdm_vendor_defined_response },
    { SPDM_ERROR, "SPDM_ERROR", dump_spdm_error },
    { SPDM_KEY_EXCHANGE_RSP, "SPDM_KEY_EXCHANGE_RSP",
      dump_spdm_key_exchange_rsp },
    { SPDM_FINISH_RSP, "SPDM_FINISH_RSP", dump_spdm_finish_rsp },
    { SPDM_PSK_EXCHANGE_RSP, "SPDM_PSK_EXCHANGE_RSP",
      dump_spdm_psk_exchange_rsp },
    { SPDM_PSK_FINISH_RSP, "SPDM_PSK_FINISH_RSP",
      dump_spdm_psk_finish_rsp },
    { SPDM_HEARTBEAT_ACK, "SPDM_HEARTBEAT_ACK", dump_spdm_heartbeat_ack },
    { SPDM_KEY_UPDATE_ACK, "SPDM_KEY_UPDATE_ACK",
      dump_spdm_key_update_ack },
    { SPDM_ENCAPSULATED_REQUEST, "SPDM_ENCAPSULATED_REQUEST",
      dump_spdm_encapsulated_request },
    { SPDM_ENCAPSULATED_RESPONSE_ACK, "SPDM_ENCAPSULATED_RESPONSE_ACK",
      dump_spdm_encapsulated_response_ack },
    { SPDM_END_SESSION_ACK, "SPDM_END_SESSION_ACK",
      dump_spdm_end_session_ack },
    { SPDM_CSR, "SPDM_CSR",
      dump_spdm_csr },
    { SPDM_SET_CERTIFICATE_RSP, "SPDM_SET_CERTIFICATE_RSP",
      dump_spdm_set_certificate_rsp },
    { SPDM_KEY_PAIR_INFO, "SPDM_KEY_PAIR_INFO",
      dump_spdm_key_pair_info },
    { SPDM_SET_KEY_PAIR_INFO_ACK, "SPDM_SET_KEY_PAIR_INFO_ACK",
      dump_spdm_set_key_pair_info_ack },
    { SPDM_CHUNK_SEND_ACK, "SPDM_CHUNK_SEND_ACK",
      dump_spdm_chunk_send_ack },
    { SPDM_CHUNK_RESPONSE, "SPDM_CHUNK_RESPONSE",
      dump_spdm_chunk_response },

    { SPDM_GET_DIGESTS, "SPDM_GET_DIGESTS", dump_spdm_get_digests },
    { SPDM_GET_CERTIFICATE, "SPDM_GET_CERTIFICATE",
      dump_spdm_get_certificate },
    { SPDM_CHALLENGE, "SPDM_CHALLENGE", dump_spdm_challenge },
    { SPDM_GET_VERSION, "SPDM_GET_VERSION", dump_spdm_get_version },
    { SPDM_GET_MEASUREMENTS, "SPDM_GET_MEASUREMENTS",
      dump_spdm_get_measurements },
    { SPDM_GET_MEASUREMENT_EXTENSION_LOG, "SPDM_GET_MEASUREMENT_EXTENSION_LOG",
      dump_spdm_get_mel },
    { SPDM_GET_CAPABILITIES, "SPDM_GET_CAPABILITIES",
      dump_spdm_get_capabilities },
    { SPDM_NEGOTIATE_ALGORITHMS, "SPDM_NEGOTIATE_ALGORITHMS",
      dump_spdm_negotiate_algorithms },
    { SPDM_VENDOR_DEFINED_REQUEST, "SPDM_VENDOR_DEFINED_REQUEST",
      dump_spdm_vendor_defined_request },
    { SPDM_RESPOND_IF_READY, "SPDM_RESPOND_IF_READY",
      dump_spdm_respond_if_ready },
    { SPDM_KEY_EXCHANGE, "SPDM_KEY_EXCHANGE", dump_spdm_key_exchange },
    { SPDM_FINISH, "SPDM_FINISH", dump_spdm_finish },
    { SPDM_PSK_EXCHANGE, "SPDM_PSK_EXCHANGE", dump_spdm_psk_exchange },
    { SPDM_PSK_FINISH, "SPDM_PSK_FINISH", dump_spdm_psk_finish },
    { SPDM_HEARTBEAT, "SPDM_HEARTBEAT", dump_spdm_heartbeat },
    { SPDM_KEY_UPDATE, "SPDM_KEY_UPDATE", dump_spdm_key_update },
    { SPDM_GET_ENCAPSULATED_REQUEST, "SPDM_GET_ENCAPSULATED_REQUEST",
      dump_spdm_get_encapsulated_request },
    { SPDM_DELIVER_ENCAPSULATED_RESPONSE,
      "SPDM_DELIVER_ENCAPSULATED_RESPONSE",
      dump_spdm_deliver_encapsulated_response },
    { SPDM_END_SESSION, "SPDM_END_SESSION", dump_spdm_end_session },
    { SPDM_GET_CSR, "SPDM_GET_CSR",
      dump_spdm_get_csr },
    { SPDM_SET_CERTIFICATE, "SPDM_SET_CERTIFICATE",
      dump_spdm_set_certificate },
    { SPDM_GET_KEY_PAIR_INFO, "SPDM_GET_KEY_PAIR_INFO",
      dump_spdm_get_key_pair_info },
    { SPDM_SET_KEY_PAIR_INFO, "SPDM_SET_KEY_PAIR_INFO",
      dump_spdm_set_key_pair_info },
    { SPDM_CHUNK_SEND, "SPDM_CHUNK_SEND",
      dump_spdm_chunk_send },
    { SPDM_CHUNK_GET, "SPDM_CHUNK_GET",
      dump_spdm_chunk_get },
};

void dump_spdm_message(const void *buffer, size_t buffer_size)
{
    const spdm_message_header_t *SpdmHeader;

    if (buffer_size < sizeof(spdm_message_header_t)) {
        printf("\n");
        return;
    }

    SpdmHeader = buffer;

    if (!m_encapsulated && !m_decrypted && !m_chunk_large_message) {
        if ((SpdmHeader->request_response_code & 0x80) != 0) {
            printf("REQ->RSP ");
        } else {
            printf("RSP->REQ ");
        }
    }
    printf("SPDM(%02x, 0x%02x) ", SpdmHeader->spdm_version,
           SpdmHeader->request_response_code);

    dump_dispatch_message(m_spdm_dispatch, LIBSPDM_ARRAY_SIZE(m_spdm_dispatch),
                          SpdmHeader->request_response_code,
                          (uint8_t *)buffer, buffer_size);

    if (m_param_dump_hex) {
        if (m_encapsulated) {
            printf("  Encapsulated SPDM Message:\n");
        } else if (m_chunk_large_message) {
            printf("  Chunk Large SPDM Message:\n");
        } else {
            printf("  SPDM Message:\n");
        }

        dump_hex(buffer, buffer_size);
    }
}

bool init_spdm_dump(void)
{
    libspdm_data_parameter_t parameter;

    m_spdm_dec_message_buffer = (void *)malloc(get_max_packet_length());
    if (m_spdm_dec_message_buffer == NULL) {
        printf("!!!memory out of resources!!!\n");
        goto error;
    }
    m_spdm_last_message_buffer = (void *)malloc(get_max_packet_length());
    if (m_spdm_last_message_buffer == NULL) {
        printf("!!!memory out of resources!!!\n");
        goto error;
    }
    m_spdm_cert_chain_buffer = (void *)malloc(LIBSPDM_MAX_CERT_CHAIN_SIZE);
    if (m_spdm_cert_chain_buffer == NULL) {
        printf("!!!memory out of resources!!!\n");
        goto error;
    }
    m_local_used_cert_chain_buffer =
        (void *)malloc(LIBSPDM_MAX_CERT_CHAIN_SIZE);
    if (m_local_used_cert_chain_buffer == NULL) {
        printf("!!!memory out of resources!!!\n");
        goto error;
    }
    m_peer_cert_chain_buffer = (void *)malloc(LIBSPDM_MAX_CERT_CHAIN_SIZE);
    if (m_peer_cert_chain_buffer == NULL) {
        printf("!!!memory out of resources!!!\n");
        goto error;
    }

    m_spdm_mel_buffer = (void *)malloc(LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE);
    if (m_spdm_mel_buffer == NULL) {
        printf("!!!memory out of resources!!!\n");
        goto error;
    }

    m_spdm_context = (void *)malloc(libspdm_get_context_size());
    if (m_spdm_context == NULL) {
        printf("!!!memory out of resources!!!\n");
        goto error;
    }
    libspdm_init_context(m_spdm_context);


    /* Provision data in case the GET_CAPABILITIES or NEGOTIATE_ALGORITHMS are not sent.*/

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &m_spdm_requester_capabilities_flags, sizeof(uint32_t));
    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &m_spdm_responder_capabilities_flags, sizeof(uint32_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &m_spdm_measurement_spec, sizeof(uint8_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
                     &parameter, &m_spdm_measurement_hash_algo,
                     sizeof(uint32_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &m_spdm_base_asym_algo, sizeof(uint32_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &m_spdm_base_hash_algo, sizeof(uint32_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_DHE_NAME_GROUP, &parameter,
                     &m_spdm_dhe_named_group, sizeof(uint16_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_AEAD_CIPHER_SUITE, &parameter,
                     &m_spdm_aead_cipher_suite, sizeof(uint16_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_REQ_BASE_ASYM_ALG, &parameter,
                     &m_spdm_req_base_asym_alg, sizeof(uint16_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_KEY_SCHEDULE, &parameter,
                     &m_spdm_key_schedule, sizeof(uint16_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_OTHER_PARAMS_SUPPORT, &parameter,
                     &m_spdm_other_params_support, sizeof(uint8_t));
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_MEL_SPEC, &parameter,
                     &m_spdm_mel_spec, sizeof(uint8_t));

    return true;

error:
    if (m_spdm_dec_message_buffer != NULL) {
        free(m_spdm_dec_message_buffer);
        m_spdm_dec_message_buffer = NULL;
    }
    if (m_spdm_last_message_buffer != NULL) {
        free(m_spdm_last_message_buffer);
        m_spdm_last_message_buffer = NULL;
    }
    if (m_spdm_cert_chain_buffer != NULL) {
        free(m_spdm_cert_chain_buffer);
        m_spdm_cert_chain_buffer = NULL;
    }
    if (m_local_used_cert_chain_buffer != NULL) {
        free(m_local_used_cert_chain_buffer);
        m_local_used_cert_chain_buffer = NULL;
    }
    if (m_peer_cert_chain_buffer != NULL) {
        free(m_peer_cert_chain_buffer);
        m_peer_cert_chain_buffer = NULL;
    }
    if (m_spdm_mel_buffer != NULL) {
        free(m_spdm_mel_buffer);
        m_spdm_mel_buffer = NULL;
    }
    if (m_spdm_context != NULL) {
        free(m_spdm_context);
        m_spdm_context = NULL;
    }
    return false;
}

void deinit_spdm_dump(void)
{
    free(m_spdm_dec_message_buffer);
    free(m_spdm_last_message_buffer);
    free(m_spdm_cert_chain_buffer);
    free(m_local_used_cert_chain_buffer);
    free(m_peer_cert_chain_buffer);
    free(m_spdm_mel_buffer);
    free(m_spdm_context);
}
