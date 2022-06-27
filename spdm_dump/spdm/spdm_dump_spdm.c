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

void *m_spdm_cert_chain_buffer;
size_t m_spdm_cert_chain_buffer_size;
size_t m_cached_spdm_cert_chain_buffer_offset;

void *m_local_used_cert_chain_buffer;
size_t m_local_used_cert_chain_buffer_size;
void *m_peer_cert_chain_buffer;
size_t m_peer_cert_chain_buffer_size;

uint32_t m_spdm_requester_capabilities_flags;
uint32_t m_spdm_responder_capabilities_flags;
uint8_t m_spdm_measurement_spec;
uint32_t m_spdm_measurement_hash_algo;
uint32_t m_spdm_base_asym_algo;
uint32_t m_spdm_base_hash_algo;
uint16_t m_spdm_dhe_named_group;
uint16_t m_spdm_aead_cipher_suite;
uint16_t m_spdm_req_base_asym_alg;
uint16_t m_spdm_key_schedule;
uint8_t m_spdm_other_params_support;

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
    { SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF, "DMTF" },
};
size_t m_spdm_measurement_spec_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_measurement_spec_value_string_table);

value_string_entry_t m_spdm_other_param_value_string_table[] = {
    { SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1, "OPAQUE_FMT_1" },
};
size_t m_spdm_other_param_value_string_table_count =
    LIBSPDM_ARRAY_SIZE(m_spdm_other_param_value_string_table);

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

    message_size = LIBSPDM_OFFSET_OF(spdm_get_capabilities_request_t, reserved);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (spdm_request->header.spdm_version >= SPDM_MESSAGE_VERSION_11) {
        message_size = LIBSPDM_OFFSET_OF(spdm_get_capabilities_request_t, data_transfer_size);
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

    message_size = LIBSPDM_OFFSET_OF(spdm_capabilities_response_t, data_transfer_size);
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

    if (!m_param_quite_mode) {
        printf("(MeasSpec=0x%02x(",
               spdm_response->measurement_specification_sel);
        dump_entry_value(
            m_spdm_measurement_spec_value_string_table,
            LIBSPDM_ARRAY_SIZE(m_spdm_measurement_spec_value_string_table),
            spdm_response->measurement_specification_sel);
        if (spdm_response->header.spdm_version >=
            SPDM_MESSAGE_VERSION_12) {
            printf("), OtherParam=0x%02x(", spdm_response->other_params_support);
            dump_entry_value(m_spdm_other_param_value_string_table,
                             LIBSPDM_ARRAY_SIZE(m_spdm_other_param_value_string_table),
                             spdm_response->other_params_support);
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
            }
            ext_alg_count = struct_table->alg_count & 0xF;
            struct_table =
                (void *)((size_t)struct_table +
                         sizeof(spdm_negotiate_algorithms_common_struct_table_t) +
                         sizeof(uint32_t) * ext_alg_count);
        }
    }

    if (spdm_response->header.spdm_version >= SPDM_MESSAGE_VERSION_12) {
        m_spdm_other_params_support = spdm_response->other_params_support;
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

    hash_size = libspdm_get_hash_size(m_spdm_base_hash_algo);

    message_size += slot_count * hash_size;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(SlotMask=0x%02x) ", spdm_response->header.param2);

        if (m_param_all_mode) {
            digest = (void *)(spdm_response + 1);
            for (index = 0; index < slot_count; index++) {
                printf("\n    Digest_%d(", (uint32_t)index);
                dump_data(digest, hash_size);
                printf(")");
                digest += hash_size;
            }
        }
    }

    printf("\n");
}

void dump_spdm_get_certificate(const void *buffer, size_t buffer_size)
{
    const spdm_get_certificate_request_t *spdm_request;
    size_t message_size;

    printf("SPDM_GET_CERTIFICATE ");

    message_size = sizeof(spdm_get_certificate_request_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_request = buffer;

    if (!m_param_quite_mode) {
        printf("(SlotID=0x%02x, Offset=0x%x, Length=0x%x) ",
               spdm_request->header.param1, spdm_request->offset,
               spdm_request->length);
    }

    m_cached_spdm_cert_chain_buffer_offset = spdm_request->offset;

    printf("\n");
}

void dump_spdm_certificate(const void *buffer, size_t buffer_size)
{
    const spdm_certificate_response_t *spdm_response;
    size_t message_size;
    void *cert_chain;
    size_t cert_chain_size;
    size_t hash_size;
    spdm_cert_chain_t *spdm_cert_chain;
    uint8_t *root_hash;

    printf("SPDM_CERTIFICATE ");

    message_size = sizeof(spdm_certificate_response_t);
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
        printf("(SlotID=0x%02x, PortLen=0x%x, RemLen=0x%x) ",
               spdm_response->header.param1,
               spdm_response->portion_length,
               spdm_response->remainder_length);
    }

    if (m_cached_spdm_cert_chain_buffer_offset +
        spdm_response->portion_length >
        LIBSPDM_MAX_CERT_CHAIN_SIZE) {
        printf(
            "SPDM cert_chain is too larger. Please increase LIBSPDM_MAX_CERT_CHAIN_SIZE and rebuild.\n");
        exit(0);
    }
    memcpy((uint8_t *)m_spdm_cert_chain_buffer +
           m_cached_spdm_cert_chain_buffer_offset,
           (spdm_response + 1), spdm_response->portion_length);
    m_spdm_cert_chain_buffer_size = m_cached_spdm_cert_chain_buffer_offset +
                                    spdm_response->portion_length;

    hash_size = libspdm_get_hash_size(m_spdm_base_hash_algo);

    if (spdm_response->remainder_length == 0) {
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
            if (spdm_response->remainder_length == 0) {
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

    if (spdm_response->remainder_length == 0) {
        cert_chain = (uint8_t *)m_spdm_cert_chain_buffer;
        cert_chain_size = m_spdm_cert_chain_buffer_size;

        if (m_encapsulated) {
            if (m_param_out_rsq_cert_chain_file_name != NULL) {
                if (!write_output_file(
                        m_param_out_rsq_cert_chain_file_name,
                        cert_chain, cert_chain_size)) {
                    printf("Fail to write out_req_cert_chain\n");
                }
            }
            if (m_requester_cert_chain_buffer == NULL ||
                m_requester_cert_chain_buffer_size == 0) {
                m_requester_cert_chain_buffer =
                    malloc(cert_chain_size);
                if (m_requester_cert_chain_buffer != NULL) {
                    memcpy(m_requester_cert_chain_buffer,
                           cert_chain, cert_chain_size);
                    m_requester_cert_chain_buffer_size =
                        cert_chain_size;
                }
            }
        } else {
            if (m_param_out_rsp_cert_chain_file_name != NULL) {
                if (!write_output_file(
                        m_param_out_rsp_cert_chain_file_name,
                        cert_chain, cert_chain_size)) {
                    printf("Fail to write out_rsp_cert_chain\n");
                }
            }
            if (m_responder_cert_chain_buffer == NULL ||
                m_responder_cert_chain_buffer_size == 0) {
                m_responder_cert_chain_buffer =
                    malloc(cert_chain_size);
                if (m_responder_cert_chain_buffer != NULL) {
                    memcpy(m_responder_cert_chain_buffer,
                           cert_chain, cert_chain_size);
                    m_responder_cert_chain_buffer_size =
                        cert_chain_size;
                }
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
            dump_data(spdm_request->nonce, 32);
            printf(")");
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
    uint8_t *signature;

    printf("SPDM_CHALLENGE_AUTH ");

    hash_size = libspdm_get_hash_size(m_spdm_base_hash_algo);
    signature_size = libspdm_get_asym_signature_size(m_spdm_base_asym_algo);
    measurement_summary_hash_size =
        spdm_dump_get_measurement_summary_hash_size(
            m_cached_measurement_summary_hash_type);

    message_size = sizeof(spdm_challenge_auth_response_t) + hash_size + 32 +
                   measurement_summary_hash_size + sizeof(uint16_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    opaque_length =
        *(uint16_t *)((size_t)buffer +
                      sizeof(spdm_challenge_auth_response_t) + hash_size +
                      32 + measurement_summary_hash_size);
    message_size += opaque_length + signature_size;
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;

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
            dump_data(nonce, 32);
            printf(")");
            measurement_summary_hash = nonce + 32;
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
            signature = opaque_data + opaque_length;
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

    printf("SPDM_GET_MEASUREMENTS ");

    message_size = LIBSPDM_OFFSET_OF(spdm_get_measurements_request_t, nonce);
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
            message_size = LIBSPDM_OFFSET_OF(
                spdm_get_measurements_request_t, slot_id_param);
        }
    }
    if (buffer_size < message_size) {
        printf("\n");
        return;
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
                dump_data(spdm_request->nonce, 32);
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
            SPDM_MEASUREMENT_BLOCK_HEADER_SPECIFICATION_DMTF) {
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
                       device_mode.operational_mode_capabilties);
                dump_entry_flags(
                    m_spdm_measurement_device_operation_mode_value_string_table,
                    LIBSPDM_ARRAY_SIZE(m_spdm_measurement_device_operation_mode_value_string_table),
                    device_mode.operational_mode_capabilties);
                printf("), OpStat=0x%08x(", device_mode.operational_mode_state);
                dump_entry_flags(
                    m_spdm_measurement_device_operation_mode_value_string_table,
                    LIBSPDM_ARRAY_SIZE(m_spdm_measurement_device_operation_mode_value_string_table),
                    device_mode.operational_mode_state);
                printf("), ModCap=0x%08x(", device_mode.device_mode_capabilties);
                dump_entry_flags(
                    m_spdm_measurement_device_mode_value_string_table,
                    LIBSPDM_ARRAY_SIZE(m_spdm_measurement_device_mode_value_string_table),
                    device_mode.device_mode_capabilties);
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

    if (include_signature) {
        signature_size =
            libspdm_get_asym_signature_size(m_spdm_base_asym_algo);

        message_size += 32 + sizeof(uint16_t);
        if (buffer_size < message_size) {
            printf("\n");
            return;
        }

        opaque_length =
            *(uint16_t *)((size_t)buffer +
                          sizeof(spdm_measurements_response_t) +
                          measurement_record_length + 32);
        message_size += opaque_length + signature_size;
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
            printf("(NumOfBlocks=0x%x, MeasRecordLen=0x%x",
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
            if (include_signature) {
                nonce = measurement_record +
                        measurement_record_length;
                printf("\n    Nonce(");
                dump_data(nonce, 32);
                printf(")");
                opaque_length = *(uint16_t *)(nonce + 32);
                opaque_data = nonce + 32 + sizeof(uint16_t);
                printf("\n    OpaqueData(");
                dump_data(opaque_data, opaque_length);
                printf(")");
                dump_spdm_opaque_data(spdm_response->header.spdm_version,
                                      opaque_data, opaque_length);
                signature = opaque_data + opaque_length;
                printf("\n    Signature(");
                dump_data(signature, signature_size);
                printf(")");
            } else {
                nonce = measurement_record +
                        measurement_record_length;
                printf("\n    Nonce(");
                dump_data(nonce, 32);
                printf(")");
                opaque_length = *(uint16_t *)(nonce + 32);
                opaque_data = nonce + 32 + sizeof(uint16_t);
                printf("\n    OpaqueData(");
                dump_data(opaque_data, opaque_length);
                printf(")");
                dump_spdm_opaque_data(spdm_response->header.spdm_version,
                                      opaque_data, opaque_length);
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
        printf("(ErrCode=0x%02x, ErrData=0x%02x) ",
               spdm_response->header.param1,
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
    header_size = LIBSPDM_OFFSET_OF(spdm_vendor_defined_request_msg_t, standard_id);

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
    header_size = LIBSPDM_OFFSET_OF(spdm_vendor_defined_request_msg_t, standard_id);

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
    size_t dhe_key_size;
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
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_spdm_dhe_named_group);
    message_size += dhe_key_size + sizeof(uint16_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    opaque_length =
        *(uint16_t *)((size_t)buffer +
                      sizeof(spdm_key_exchange_request_t) + dhe_key_size);
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
            dump_data(exchange_data, dhe_key_size);
            printf(")");
            opaque_length = *(uint16_t *)((uint8_t *)exchange_data +
                                          dhe_key_size);
            opaque_data = (void *)((uint8_t *)exchange_data +
                                   dhe_key_size + sizeof(uint16_t));
            printf("\n    OpaqueData(");
            dump_data(opaque_data, opaque_length);
            printf(")");
            dump_spdm_opaque_data(spdm_request->header.spdm_version,
                                  opaque_data, opaque_length);
        }
    }

    printf("\n");

    m_cached_session_id = spdm_request->req_session_id << 16;
    memcpy(m_spdm_last_message_buffer, buffer, message_size);
    m_spdm_last_message_buffer_size = message_size;
}

void dump_spdm_key_exchange_rsp(const void *buffer, size_t buffer_size)
{
    const spdm_key_exchange_response_t *spdm_response;
    size_t message_size;
    size_t dhe_key_size;
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
    libspdm_data_parameter_t parameter;
    uint8_t mut_auth_requested;

    printf("SPDM_KEY_EXCHANGE_RSP ");

    message_size = sizeof(spdm_key_exchange_response_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    spdm_response = buffer;
    dhe_key_size = libspdm_get_dhe_pub_key_size(m_spdm_dhe_named_group);
    signature_size = libspdm_get_asym_signature_size(m_spdm_base_asym_algo);
    measurement_summary_hash_size =
        spdm_dump_get_measurement_summary_hash_size(
            m_cached_measurement_summary_hash_type);
    hmac_size = libspdm_get_hash_size(m_spdm_base_hash_algo);

    message_size +=
        dhe_key_size + measurement_summary_hash_size + sizeof(uint16_t);
    if (buffer_size < message_size) {
        printf("\n");
        return;
    }

    opaque_length = *(
        uint16_t *)((size_t)buffer + sizeof(spdm_key_exchange_response_t) +
                    dhe_key_size + measurement_summary_hash_size);
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
            dump_data(exchange_data, dhe_key_size);
            printf(")");
            measurement_summary_hash = exchange_data + dhe_key_size;
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

    m_cached_session_id =
        m_cached_session_id | spdm_response->rsp_session_id;
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
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    *(uint32_t *)parameter.additional_data = m_current_session_id;
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_SESSION_MUT_AUTH_REQUESTED,
                     &parameter, &mut_auth_requested,
                     sizeof(mut_auth_requested));

    if (spdm_dump_session_data_provision(m_spdm_context,
                                         m_current_session_id, false,
                                         true) != LIBSPDM_STATUS_SUCCESS) {
        return;
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

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_handshake_key[%x]\n",
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
    signature_size =
        libspdm_get_req_asym_signature_size(m_spdm_req_base_asym_alg);
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

    if (spdm_dump_session_data_provision(m_spdm_context,
                                         m_current_session_id, true,
                                         true) != LIBSPDM_STATUS_SUCCESS) {
        return;
    }

    libspdm_append_message_f(m_spdm_context, m_current_session_info, true,
                             m_spdm_last_message_buffer,
                             m_spdm_last_message_buffer_size);
    libspdm_append_message_f(m_spdm_context, m_current_session_info, true, buffer, message_size);

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_data_key[%x]\n",
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

    m_cached_session_id = spdm_request->req_session_id << 16;
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
    libspdm_data_parameter_t parameter;
    bool use_psk;

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

    m_cached_session_id =
        m_cached_session_id | spdm_response->rsp_session_id;
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

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_handshake_key[%x]\n",
                   m_current_session_id));

    libspdm_calculate_th1_hash(m_spdm_context, m_current_session_info, true,
                               th1_hash_data);
    libspdm_secured_message_set_use_psk(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        false);

    use_psk = false;
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    *(uint32_t *)parameter.additional_data = m_current_session_id;
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_SESSION_USE_PSK, &parameter,
                     &use_psk, sizeof(use_psk));

    libspdm_generate_session_handshake_key(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        th1_hash_data);

    use_psk = true;
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    *(uint32_t *)parameter.additional_data = m_current_session_id;
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_SESSION_USE_PSK, &parameter,
                     &use_psk, sizeof(use_psk));

    libspdm_secured_message_set_use_psk(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        true);
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
        libspdm_secured_message_set_use_psk(
            libspdm_get_secured_message_context_via_session_info(
                m_current_session_info),
            false);

        use_psk = false;
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
        *(uint32_t *)parameter.additional_data = m_current_session_id;
        libspdm_set_data(m_spdm_context, LIBSPDM_DATA_SESSION_USE_PSK,
                         &parameter, &use_psk, sizeof(use_psk));

        libspdm_generate_session_data_key(
            libspdm_get_secured_message_context_via_session_info(
                m_current_session_info),
            th2_hash_data);

        use_psk = true;
        libspdm_zero_mem(&parameter, sizeof(parameter));
        parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
        *(uint32_t *)parameter.additional_data = m_current_session_id;
        libspdm_set_data(m_spdm_context, LIBSPDM_DATA_SESSION_USE_PSK,
                         &parameter, &use_psk, sizeof(use_psk));

        libspdm_secured_message_set_use_psk(
            libspdm_get_secured_message_context_via_session_info(
                m_current_session_info),
            true);
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
    libspdm_append_message_f(m_spdm_context, m_current_session_info, true, buffer, message_size);
}

void dump_spdm_psk_finish_rsp(const void *buffer, size_t buffer_size)
{
    size_t message_size;
    uint8_t th2_hash_data[64];
    libspdm_data_parameter_t parameter;
    bool use_psk;

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

    if (spdm_dump_session_data_provision(m_spdm_context,
                                         m_current_session_id, true,
                                         true) != LIBSPDM_STATUS_SUCCESS) {
        return;
    }

    libspdm_append_message_f(m_spdm_context, m_current_session_info, true, buffer, message_size);

    LIBSPDM_DEBUG((LIBSPDM_DEBUG_INFO, "libspdm_generate_session_data_key[%x]\n",
                   m_current_session_id));

    if (spdm_dump_session_data_check(m_spdm_context, m_current_session_id,
                                     true) != LIBSPDM_STATUS_SUCCESS) {
        return;
    }
    libspdm_calculate_th2_hash(m_spdm_context, m_current_session_info, true,
                               th2_hash_data);
    libspdm_secured_message_set_use_psk(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        false);

    use_psk = false;
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    *(uint32_t *)parameter.additional_data = m_current_session_id;
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_SESSION_USE_PSK, &parameter,
                     &use_psk, sizeof(use_psk));

    libspdm_generate_session_data_key(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        th2_hash_data);

    use_psk = true;
    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    *(uint32_t *)parameter.additional_data = m_current_session_id;
    libspdm_set_data(m_spdm_context, LIBSPDM_DATA_SESSION_USE_PSK, &parameter,
                     &use_psk, sizeof(use_psk));

    libspdm_secured_message_set_use_psk(
        libspdm_get_secured_message_context_via_session_info(
            m_current_session_info),
        true);
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

        if (!m_param_quite_mode) {
            printf("(ReqSlotID=0x%02x) ",
                   *((uint8_t *)buffer + header_size));
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

dispatch_table_entry_t m_spdm_dispatch[] = {
    { SPDM_DIGESTS, "SPDM_DIGESTS", dump_spdm_digests },
    { SPDM_CERTIFICATE, "SPDM_CERTIFICATE", dump_spdm_certificate },
    { SPDM_CHALLENGE_AUTH, "SPDM_CHALLENGE_AUTH",
      dump_spdm_challenge_auth },
    { SPDM_VERSION, "SPDM_VERSION", dump_spdm_version },
    { SPDM_MEASUREMENTS, "SPDM_MEASUREMENTS", dump_spdm_measurements },
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

    { SPDM_GET_DIGESTS, "SPDM_GET_DIGESTS", dump_spdm_get_digests },
    { SPDM_GET_CERTIFICATE, "SPDM_GET_CERTIFICATE",
      dump_spdm_get_certificate },
    { SPDM_CHALLENGE, "SPDM_CHALLENGE", dump_spdm_challenge },
    { SPDM_GET_VERSION, "SPDM_GET_VERSION", dump_spdm_get_version },
    { SPDM_GET_MEASUREMENTS, "SPDM_GET_MEASUREMENTS",
      dump_spdm_get_measurements },
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
};

void dump_spdm_message(const void *buffer, size_t buffer_size)
{
    const spdm_message_header_t *SpdmHeader;

    if (buffer_size < sizeof(spdm_message_header_t)) {
        printf("\n");
        return;
    }

    SpdmHeader = buffer;

    if (!m_encapsulated && !m_decrypted) {
        if ((SpdmHeader->request_response_code & 0x80) != 0) {
            printf("REQ->RSP ");
        } else {
            printf("RSP->REQ ");
        }
    }
    printf("SPDM(%x, 0x%02x) ", SpdmHeader->spdm_version,
           SpdmHeader->request_response_code);

    dump_dispatch_message(m_spdm_dispatch, LIBSPDM_ARRAY_SIZE(m_spdm_dispatch),
                          SpdmHeader->request_response_code,
                          (uint8_t *)buffer, buffer_size);

    if (m_param_dump_hex) {
        if (!m_encapsulated) {
            printf("  SPDM Message:\n");
        } else {
            printf("  Encapsulated SPDM Message:\n");
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
    if (m_local_used_cert_chain_buffer == NULL) {
        free(m_local_used_cert_chain_buffer);
        m_local_used_cert_chain_buffer = NULL;
    }
    if (m_peer_cert_chain_buffer == NULL) {
        free(m_peer_cert_chain_buffer);
        m_peer_cert_chain_buffer = NULL;
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
    free(m_spdm_context);
}
