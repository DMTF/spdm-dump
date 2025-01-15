/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

bool m_param_quite_mode;
bool m_param_all_mode;
bool m_param_dump_vendor_app;
bool m_param_dump_hex;
/* 0 = SPDM, 1 = RAW */
uint32_t m_cert_chain_format = 0;
char *m_param_out_rsp_cert_chain_file_name[SPDM_MAX_SLOT_COUNT] = {NULL};
char *m_param_out_rsq_cert_chain_file_name[SPDM_MAX_SLOT_COUNT] = {NULL};
/* cert_chain_data is from end user.
 * If cert_chain_format is SPDM, it includes spdm_cert_chain_t header.
 * If cert_chain_format is RAW, it does not include spdm_cert_chain_t header. */
size_t m_requester_cert_chain_data_size[SPDM_MAX_SLOT_COUNT+1] = {0};
void *m_requester_cert_chain_data[SPDM_MAX_SLOT_COUNT+1] = {NULL};
size_t m_responder_cert_chain_data_size[SPDM_MAX_SLOT_COUNT+1] = {0};
void *m_responder_cert_chain_data[SPDM_MAX_SLOT_COUNT+1] = {NULL};
/* cert_chain_buffer is from transport message.
 * It always includes spdm_cert_chain_t header */
size_t m_requester_cert_chain_buffer_size[SPDM_MAX_SLOT_COUNT+1] = {0};
void *m_requester_cert_chain_buffer[SPDM_MAX_SLOT_COUNT+1] = {NULL};
size_t m_responder_cert_chain_buffer_size[SPDM_MAX_SLOT_COUNT+1] = {0};
void *m_responder_cert_chain_buffer[SPDM_MAX_SLOT_COUNT+1] = {NULL};

extern uint32_t m_spdm_requester_capabilities_flags;
extern uint32_t m_spdm_responder_capabilities_flags;
extern uint8_t m_spdm_measurement_spec;
extern uint32_t m_spdm_measurement_hash_algo;
extern uint32_t m_spdm_base_asym_algo;
extern uint32_t m_spdm_base_hash_algo;
extern uint16_t m_spdm_dhe_named_group;
extern uint16_t m_spdm_aead_cipher_suite;
extern uint16_t m_spdm_req_base_asym_alg;
extern uint16_t m_spdm_key_schedule;
extern uint8_t m_spdm_other_params_support;
extern uint8_t m_spdm_mel_spec;

extern value_string_entry_t m_spdm_requester_capabilities_string_table[];
extern size_t m_spdm_requester_capabilities_string_table_count;
extern value_string_entry_t m_spdm_responder_capabilities_string_table[];
extern size_t m_spdm_responder_capabilities_string_table_count;
extern value_string_entry_t m_spdm_hash_value_string_table[];
extern size_t m_spdm_hash_value_string_table_count;
extern value_string_entry_t m_spdm_measurement_hash_value_string_table[];
extern size_t m_spdm_measurement_hash_value_string_table_count;
extern value_string_entry_t m_spdm_asym_value_string_table[];
extern size_t m_spdm_asym_value_string_table_count;
extern value_string_entry_t m_spdm_dhe_value_string_table[];
extern size_t m_spdm_dhe_value_string_table_count;
extern value_string_entry_t m_spdm_aead_value_string_table[];
extern size_t m_spdm_aead_value_string_table_count;
extern value_string_entry_t m_spdm_key_schedule_value_string_table[];
extern size_t m_spdm_key_schedule_value_string_table_count;
extern value_string_entry_t m_spdm_measurement_spec_value_string_table[];
extern size_t m_spdm_measurement_spec_value_string_table_count;
extern value_string_entry_t m_spdm_other_param_value_string_table[];
extern size_t m_spdm_other_param_value_string_table_count;
extern value_string_entry_t m_spdm_mel_spec_value_string_table[];
extern size_t m_spdm_mel_spec_value_string_table_count;

value_string_entry_t m_cert_chain_format_string_table[] = {
    { CERT_CHAIN_FORMAT_SPDM, "SPDM" },
    { CERT_CHAIN_FORMAT_RAW, "RAW" },
};

value_string_entry_t m_slot_id_string_table_with_ff[] = {
    { 0x0, "0" }, { 0x1, "1" }, { 0x2, "2" },
    { 0x3, "3" }, { 0x4, "4" }, { 0x5, "5" },
    { 0x6, "6" }, { 0x7, "7" }, { 0x8, "0xFF" },
};

value_string_entry_t m_slot_id_string_table_without_ff[] = {
    { 0x0, "0" }, { 0x1, "1" }, { 0x2, "2" },
    { 0x3, "3" }, { 0x4, "4" }, { 0x5, "5" },
    { 0x6, "6" }, { 0x7, "7" },
};

dispatch_table_entry_t *
get_dispatch_entry_by_id(dispatch_table_entry_t *dispatch_table,
                         size_t dispatch_table_count, uint32_t id)
{
    size_t index;

    for (index = 0; index < dispatch_table_count; index++) {
        if (dispatch_table[index].id == id) {
            return &dispatch_table[index];
        }
    }
    return NULL;
}

void dump_dispatch_message(dispatch_table_entry_t *dispatch_table,
                           size_t dispatch_table_count, uint32_t id,
                           const void *buffer, size_t buffer_size)
{
    dispatch_table_entry_t *entry;

    entry = get_dispatch_entry_by_id(dispatch_table, dispatch_table_count,
                                     id);
    if (entry != NULL) {
        if (entry->dump_func != NULL) {
            entry->dump_func(buffer, buffer_size);
        } else if (entry->name != NULL) {
            printf("%s\n", entry->name);
        }
    } else {
        printf("<Unknown>\n");
    }
}

void dump_entry_flags(const value_string_entry_t *entry_table,
                      size_t entry_table_count, uint32_t flags)
{
    size_t index;
    bool first;

    first = true;
    for (index = 0; index < entry_table_count; index++) {
        if ((entry_table[index].value & flags) != 0) {
            if (first) {
                first = false;
            } else {
                printf(",");
            }
            printf("%s", entry_table[index].name);
        }
    }
}

void dump_entry_flags_all(const value_string_entry_t *entry_table,
                          size_t entry_table_count, uint32_t flags)
{
    size_t index;

    for (index = 0; index < entry_table_count; index++) {
        if (index != 0) {
            printf(", ");
        }
        printf("%s=%d", entry_table[index].name,
               ((entry_table[index].value & flags) != 0) ? 1 : 0);
    }
}

void dump_entry_value(const value_string_entry_t *entry_table,
                      size_t entry_table_count, uint32_t value)
{
    size_t index;

    for (index = 0; index < entry_table_count; index++) {
        if (entry_table[index].value == value) {
            printf("%s", entry_table[index].name);
            return;
        }
    }
    printf("<Unknown>");
}

bool get_value_from_name(const value_string_entry_t *table,
                         size_t entry_count, const char *name,
                         uint32_t *value)
{
    size_t index;

    for (index = 0; index < entry_count; index++) {
        if (strcmp(name, table[index].name) == 0) {
            *value = table[index].value;
            return true;
        }
    }
    return false;
}

bool get_flags_from_name(const value_string_entry_t *table,
                         size_t entry_count, const char *name,
                         uint32_t *flags)
{
    uint32_t value;
    char *flag_name;
    char *local_name;
    bool ret;

    local_name = (void *)malloc(strlen(name) + 1);
    if (local_name == NULL) {
        return false;
    }
    strcpy(local_name, name);


    /* name = Flag1,Flag2,...,FlagN*/

    *flags = 0;
    flag_name = strtok(local_name, ",");
    while (flag_name != NULL) {
        if (!get_value_from_name(table, entry_count, flag_name,
                                 &value)) {
            printf("unsupported flag - %s\n", flag_name);
            ret = false;
            goto done;
        }
        *flags |= value;
        flag_name = strtok(NULL, ",");
    }
    if (*flags == 0) {
        ret = false;
    } else {
        ret = true;
    }
done:
    free(local_name);
    return ret;
}

void print_usage(void)
{
    printf("\n%s -r <pcap_file_name>\n", "spdm_dump");
    printf("   [-q] (quite mode, dump message type only)\n");
    printf("   [-a] (all mode, dump all fields)\n");
    printf("   [-d] (dump application message)\n");
    printf("   [-x] (dump message in hex)\n");
    printf("   [--psk <pre-shared key>]\n");
    printf("   [--dhe_secret <session DHE secret>]\n");
    printf("   [--kem_secret <session KEM secret>]\n");
    printf(
        "   [--req_cap       CERT|CHAL|                                ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|                 ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID|                                EP_INFO_NO_SIG|EP_INFO_SIG|    EVENT|MULTI_KEY_ONLY|MULTI_KEY_NEG|                                                       LARGE_CERT]\n");
    printf(
        "   [--rsp_cap CACHE|CERT|CHAL|MEAS_NO_SIG|MEAS_SIG|MEAS_FRESH|ENCRYPT|MAC|MUT_AUTH|KEY_EX|PSK|PSK_WITH_CONTEXT|ENCAP|HBEAT|KEY_UPD|HANDSHAKE_IN_CLEAR|PUB_KEY_ID|SET_CERT|CSR|CERT_INSTALL_RESET|EP_INFO_NO_SIG|EP_INFO_SIG|MEL|EVENT|MULTI_KEY_ONLY|MULTI_KEY_NEG|GET_KEY_PAIR_INFO|SET_KEY_PAIR_INFO|SET_KEY_PAIR_RESET|LARGE_CERT]\n");
    printf("   [--hash SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512|SM3_256]\n");
    printf("   [--meas_spec DMTF]\n");
    printf("   [--meas_hash RAW_BIT|SHA_256|SHA_384|SHA_512|SHA3_256|SHA3_384|SHA3_512|SM3_256]\n");
    printf("   [--mel_spec DMTF]\n");
    printf(
        "   [--asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521|SM2_P256|EDDSA_25519|EDDSA_448]\n");
    printf(
        "   [--req_asym RSASSA_2048|RSASSA_3072|RSASSA_4096|RSAPSS_2048|RSAPSS_3072|RSAPSS_4096|ECDSA_P256|ECDSA_P384|ECDSA_P521|SM2_P256|EDDSA_25519|EDDSA_448]\n");
    printf(
        "   [--dhe FFDHE_2048|FFDHE_3072|FFDHE_4096|SECP_256_R1|SECP_384_R1|SECP_521_R1|SM2_P256]\n");
    printf("   [--aead AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305|SM4_128_GCM]\n");
    printf("   [--key_schedule HMAC_HASH]\n");
    printf("   [--other_param OPAQUE_FMT_1|MULTI_KEY_CONN]\n");
    printf("   [--cert_chain_format SPDM|RAW]\n");
    printf("   [--req_cert_chain_slot_id <0~7|0xFF>]\n");
    printf("   [--req_cert_chain <input requester public cert chain file>]\n");
    printf("   [--rsp_cert_chain_slot_id <0~7|0xFF>]\n");
    printf("   [--rsp_cert_chain <input responder public cert chain file>]\n");
    printf("   [--out_req_cert_chain_slot_id <0~7>]\n");
    printf("   [--out_req_cert_chain <output requester public cert chain file>]\n");
    printf("   [--out_rsp_cert_chain_slot_id <0~7>]\n");
    printf("   [--out_rsp_cert_chain <output responder public cert chain file>]\n");
    printf("\n");
    printf("NOTE:\n");
    printf("   [--psk] is required to decrypt a PSK session\n");
    printf("   [--dhe_secret] or [--kem_secret] is required to decrypt a non-PSK session\n");
    printf("      format: A hex string, whose count of char must be even.\n");
    printf("              It must not have prefix '0x'. The leading '0' must be included.\n");
    printf("              '0123CDEF' means 4 bytes 0x01, 0x23, 0xCD, 0xEF,\n");
    printf("              where 0x01 is the first byte and 0xEF is the last byte in memory\n");
    printf("\n");
    printf(
        "   [--req_cap] and [--rsp_cap] means requester capability flags and responder capability flags.\n");
    printf("      format: Capabilities can be multiple flags. Please use ',' for them.\n");
    printf(
        "   [--hash], [--meas_spec], [--meas_hash], [--asym], [--req_asym], [--dhe], [--aead], [--key_schedule], [--other_param] means negotiated algorithms.\n");
    printf("      format: Algorithms must include only one flag.\n");
    printf(
        "      Capabilities and algorithms are required if GET_CAPABILITIES or NEGOTIATE_ALGORITHMS is not sent.\n");
    printf("              For example, the negotiated state session or quick PSK session.\n");
    printf("\n");
    printf(
        "   [--cert_chain_format] is required before any cert chain file parameter. Default is SPDM.\n");
    printf(
        "      SPDM means cert chain file includes the Length, Reserved, or RootHash fields. It is needed if root_cert is absent.\n");
    printf(
        "      RAW means cert chain file does not include the Length, Reserved, or RootHash fields.\n");
    printf("   [--req_cert_chain_slot_id] is required just before [--req_cert_chain]\n");
    printf("   [--req_cert_chain] is required to if encapsulated GET_CERTIFICATE is not sent\n");
    printf("   [--rsp_cert_chain_slot_id] is required just before [--rsp_cert_chain]\n");
    printf("   [--rsp_cert_chain] is required to if GET_CERTIFICATE is not sent\n");
    printf("   [--out_req_cert_chain_slot_id] is required just before [--out_req_cert_chain]\n");
    printf("   [--out_req_cert_chain] can be used if encapsulated GET_CERTIFICATE is sent\n");
    printf("   [--out_rsp_cert_chain_slot_id] is required just before [--out_rsp_cert_chain]\n");
    printf("   [--out_rsp_cert_chain] can be used if GET_CERTIFICATE is sent\n");
    printf(
        "      format: A file containing certificates defined in SPDM spec 'certificate chain format'.\n");
    printf("              It is one or more ASN.1 DER-encoded X.509 v3 certificates.\n");
    printf(
        "              It may include multiple certificates, starting from root cert to leaf cert.\n");
    printf("              It is defined by [--cert_chain_format].\n");
}

void process_args(int argc, char *argv[])
{
    char *pcap_file_name;
    uint32_t data32;
    bool res;

    /*cert_chain_slot_id_index*/
    uint8_t rsp_slot_id_index;
    uint8_t req_slot_id_index;
    uint8_t out_rsp_slot_id_index;
    uint8_t out_req_slot_id_index;
    rsp_slot_id_index = 0;
    req_slot_id_index = 0;
    out_rsp_slot_id_index = 0;
    out_req_slot_id_index = 0;

    /*key params input time*/
    uint8_t psk_key_input_count;
    uint8_t dhe_key_input_count;
    uint8_t kem_key_input_count;
    psk_key_input_count = 0;
    dhe_key_input_count = 0;
    kem_key_input_count = 0;

    pcap_file_name = NULL;

    if (argc == 1) {
        printf("invalid, pcap file should be provided!\n");
        print_usage();
        exit(0);
    }

    argc--;
    argv++;

    if ((strcmp(argv[0], "-h") == 0) || (strcmp(argv[0], "--help") == 0)) {
        print_usage();
        exit(0);
    }

    while (argc > 0) {
        if (strcmp(argv[0], "-r") == 0) {
            if (argc >= 2) {
                pcap_file_name = argv[1];
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid -r\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "-q") == 0) {
            m_param_quite_mode = true;
            argc -= 1;
            argv += 1;
            continue;
        }

        if (strcmp(argv[0], "-a") == 0) {
            m_param_all_mode = true;
            argc -= 1;
            argv += 1;
            continue;
        }

        if (strcmp(argv[0], "-d") == 0) {
            m_param_dump_vendor_app = true;
            argc -= 1;
            argv += 1;
            continue;
        }

        if (strcmp(argv[0], "-x") == 0) {
            m_param_dump_hex = true;
            argc -= 1;
            argv += 1;
            continue;
        }

        if (strcmp(argv[0], "--psk") == 0) {
            if (argc >= 2) {
                if (psk_key_input_count >= LIBSPDM_MAX_SESSION_COUNT) {
                    printf("too many psk key input \n");
                    print_usage();
                    exit(0);
                }
                if (!hex_string_to_buffer(argv[1],
                                          &m_psk_buffer[psk_key_input_count],
                                          &m_psk_buffer_size[psk_key_input_count])) {
                    printf("invalid --psk\n");
                    print_usage();
                    exit(0);
                }
                argc -= 2;
                argv += 2;

                psk_key_input_count++;
                continue;
            } else {
                printf("invalid --psk\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--dhe_secret") == 0) {
            if (argc >= 2) {
                if (dhe_key_input_count >= LIBSPDM_MAX_SESSION_COUNT) {
                    printf("too many dhe key input \n");
                    print_usage();
                    exit(0);
                }
                if (!hex_string_to_buffer(
                        argv[1], &m_dhe_secret_buffer[dhe_key_input_count],
                        &m_dhe_secret_buffer_size[dhe_key_input_count])) {
                    printf("invalid --dhe_secret\n");
                    print_usage();
                    exit(0);
                }
                argc -= 2;
                argv += 2;

                dhe_key_input_count++;
                continue;
            } else {
                printf("invalid --dhe_secret\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--kem_secret") == 0) {
            if (argc >= 2) {
                if (dhe_key_input_count >= LIBSPDM_MAX_SESSION_COUNT) {
                    printf("too many kem key input \n");
                    print_usage();
                    exit(0);
                }
                if (!hex_string_to_buffer(
                        argv[1], &m_kem_secret_buffer[kem_key_input_count],
                        &m_kem_secret_buffer_size[kem_key_input_count])) {
                    printf("invalid --kem_secret\n");
                    print_usage();
                    exit(0);
                }
                argc -= 2;
                argv += 2;

                kem_key_input_count++;
                continue;
            } else {
                printf("invalid --kem_secret\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--req_cap") == 0) {
            if (argc >= 2) {
                if (!get_flags_from_name(
                        m_spdm_requester_capabilities_string_table,
                        m_spdm_requester_capabilities_string_table_count,
                        argv[1],
                        &m_spdm_requester_capabilities_flags)) {
                    printf("invalid --req_cap %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                printf("req_cap - 0x%08x\n",
                       m_spdm_requester_capabilities_flags);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --req_cap\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--rsp_cap") == 0) {
            if (argc >= 2) {
                if (!get_flags_from_name(
                        m_spdm_responder_capabilities_string_table,
                        m_spdm_responder_capabilities_string_table_count,
                        argv[1],
                        &m_spdm_responder_capabilities_flags)) {
                    printf("invalid --rsp_cap %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                printf("rsp_cap - 0x%08x\n",
                       m_spdm_responder_capabilities_flags);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --rsp_cap\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--hash") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_spdm_hash_value_string_table,
                        m_spdm_hash_value_string_table_count,
                        argv[1], &m_spdm_base_hash_algo)) {
                    printf("invalid --hash %s\n", argv[1]);
                    print_usage();
                    exit(0);
                }
                printf("hash - 0x%08x\n",
                       m_spdm_base_hash_algo);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --hash\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--meas_spec") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_spdm_measurement_spec_value_string_table,
                        m_spdm_measurement_spec_value_string_table_count,
                        argv[1], &data32)) {
                    printf("invalid --meas_spec %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                m_spdm_measurement_spec = (uint8_t)data32;
                printf("meas_spec - 0x%02x\n",
                       m_spdm_measurement_spec);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --meas_spec\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--meas_hash") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_spdm_measurement_hash_value_string_table,
                        m_spdm_measurement_hash_value_string_table_count,
                        argv[1],
                        &m_spdm_measurement_hash_algo)) {
                    printf("invalid --meas_hash %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                printf("meas_hash - 0x%08x\n",
                       m_spdm_measurement_hash_algo);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --meas_hash\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--mel_spec") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_spdm_mel_spec_value_string_table,
                        m_spdm_mel_spec_value_string_table_count,
                        argv[1], &data32)) {
                    printf("invalid --mel_spec %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                m_spdm_mel_spec = (uint8_t)data32;
                printf("mel_spec - 0x%02x\n",
                       m_spdm_mel_spec);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --mel_spec\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--asym") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_spdm_asym_value_string_table,
                        m_spdm_asym_value_string_table_count,
                        argv[1], &m_spdm_base_asym_algo)) {
                    printf("invalid --asym %s\n", argv[1]);
                    print_usage();
                    exit(0);
                }
                printf("asym - 0x%08x\n",
                       m_spdm_base_asym_algo);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --asym\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--req_asym") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_spdm_asym_value_string_table,
                        m_spdm_asym_value_string_table_count,
                        argv[1], &data32)) {
                    printf("invalid --req_asym %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                m_spdm_req_base_asym_alg = (uint16_t)data32;
                printf("req_asym - 0x%04x\n",
                       m_spdm_req_base_asym_alg);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --req_asym\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--dhe") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_spdm_dhe_value_string_table,
                        m_spdm_dhe_value_string_table_count,
                        argv[1], &data32)) {
                    printf("invalid --dhe %s\n", argv[1]);
                    print_usage();
                    exit(0);
                }
                m_spdm_dhe_named_group = (uint16_t)data32;
                printf("dhe - 0x%04x\n",
                       m_spdm_dhe_named_group);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --dhe\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--aead") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_spdm_aead_value_string_table,
                        m_spdm_aead_value_string_table_count,
                        argv[1], &data32)) {
                    printf("invalid --aead %s\n", argv[1]);
                    print_usage();
                    exit(0);
                }
                m_spdm_aead_cipher_suite = (uint16_t)data32;
                printf("aead - 0x%04x\n",
                       m_spdm_aead_cipher_suite);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --aead\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--key_schedule") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_spdm_key_schedule_value_string_table,
                        m_spdm_key_schedule_value_string_table_count,
                        argv[1], &data32)) {
                    printf("invalid --key_schedule %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                m_spdm_key_schedule = (uint16_t)data32;
                printf("key_schedule - 0x%04x\n",
                       m_spdm_key_schedule);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --key_schedule\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--other_param") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_spdm_other_param_value_string_table,
                        m_spdm_other_param_value_string_table_count,
                        argv[1], &data32)) {
                    printf("invalid --other_param %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                m_spdm_other_params_support = (uint8_t)data32;
                printf("other_param - 0x%04x\n",
                       m_spdm_other_params_support);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --other_param\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--cert_chain_format") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_cert_chain_format_string_table,
                        LIBSPDM_ARRAY_SIZE(m_cert_chain_format_string_table),
                        argv[1],
                        &m_cert_chain_format)) {
                    printf("invalid --cert_chain_format %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                printf("cert_chain_format - %d\n",
                       m_cert_chain_format);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --cert_chain_format\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--req_cert_chain_slot_id") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_slot_id_string_table_with_ff,
                        LIBSPDM_ARRAY_SIZE(m_slot_id_string_table_with_ff),
                        argv[1], &data32)) {
                    printf("invalid --req_cert_chain_slot_id %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                req_slot_id_index = (uint8_t)data32;
                printf("req_cert_chain_slot_id - 0x%02x\n", req_slot_id_index);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --req_cert_chain_slot_id\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--req_cert_chain") == 0) {
            if (argc >= 2) {
                if (m_requester_cert_chain_data[req_slot_id_index] != NULL) {
                    free(m_requester_cert_chain_data[req_slot_id_index]);
                }
                res = read_input_file(
                    argv[1], &m_requester_cert_chain_data[req_slot_id_index],
                    &m_requester_cert_chain_data_size[req_slot_id_index]);
                if (!res) {
                    printf("invalid --req_cert_chain\n");
                    print_usage();
                    exit(0);
                }
                if (m_requester_cert_chain_data_size[req_slot_id_index] >
                    LIBSPDM_MAX_CERT_CHAIN_SIZE) {
                    printf(
                        "req_cert_chain is too larger. Please increase LIBSPDM_MAX_CERT_CHAIN_SIZE and rebuild.\n");
                    exit(0);
                }
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --req_cert_chain\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--rsp_cert_chain_slot_id") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_slot_id_string_table_with_ff,
                        LIBSPDM_ARRAY_SIZE(m_slot_id_string_table_with_ff),
                        argv[1], &data32)) {
                    printf("invalid --rsp_cert_chain_slot_id %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                rsp_slot_id_index = (uint8_t)data32;
                printf("rsp_cert_chain_slot_id - 0x%02x\n", rsp_slot_id_index);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --rsp_cert_chain_slot_id\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--rsp_cert_chain") == 0) {
            if (argc >= 2) {
                if (m_responder_cert_chain_data[rsp_slot_id_index] != NULL) {
                    free(m_responder_cert_chain_data[rsp_slot_id_index]);
                }
                res = read_input_file(
                    argv[1], &m_responder_cert_chain_data[rsp_slot_id_index],
                    &m_responder_cert_chain_data_size[rsp_slot_id_index]);
                if (!res) {
                    printf("invalid --rsp_cert_chain\n");
                    print_usage();
                    exit(0);
                }
                if (m_responder_cert_chain_data_size[rsp_slot_id_index] >
                    LIBSPDM_MAX_CERT_CHAIN_SIZE) {
                    printf(
                        "rsp_cert_chain is too larger. Please increase LIBSPDM_MAX_CERT_CHAIN_SIZE and rebuild.\n");
                    exit(0);
                }
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --rsp_cert_chain\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--out_req_cert_chain_slot_id") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_slot_id_string_table_without_ff,
                        LIBSPDM_ARRAY_SIZE(m_slot_id_string_table_without_ff),
                        argv[1], &data32)) {
                    printf("invalid --out_req_cert_chain_slot_id %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                out_req_slot_id_index = (uint8_t)data32;
                printf("out_req_cert_chain_slot_id - 0x%02x\n", out_req_slot_id_index);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --out_req_cert_chain_slot_id\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--out_req_cert_chain") == 0) {
            if (argc >= 2) {
                m_param_out_rsq_cert_chain_file_name[out_req_slot_id_index] = argv[1];
                if (!open_output_file(
                        m_param_out_rsq_cert_chain_file_name[out_req_slot_id_index])) {
                    printf("invalid --out_req_cert_chain\n");
                    print_usage();
                    exit(0);
                }
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --out_req_cert_chain\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--out_rsp_cert_chain_slot_id") == 0) {
            if (argc >= 2) {
                if (!get_value_from_name(
                        m_slot_id_string_table_without_ff,
                        LIBSPDM_ARRAY_SIZE(m_slot_id_string_table_without_ff),
                        argv[1], &data32)) {
                    printf("invalid --out_rsp_cert_chain_slot_id %s\n",
                           argv[1]);
                    print_usage();
                    exit(0);
                }
                out_rsp_slot_id_index = (uint8_t)data32;
                printf("out_rsp_cert_chain_slot_id - 0x%02x\n", out_rsp_slot_id_index);
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --out_rsp_cert_chain_slot_id\n");
                print_usage();
                exit(0);
            }
        }

        if (strcmp(argv[0], "--out_rsp_cert_chain") == 0) {
            if (argc >= 2) {
                m_param_out_rsp_cert_chain_file_name[out_rsp_slot_id_index] = argv[1];
                if (!open_output_file(
                        m_param_out_rsp_cert_chain_file_name[out_rsp_slot_id_index])) {
                    printf("invalid --out_rsp_cert_chain\n");
                    print_usage();
                    exit(0);
                }
                argc -= 2;
                argv += 2;
                continue;
            } else {
                printf("invalid --out_rsp_cert_chain\n");
                print_usage();
                exit(0);
            }
        }

        printf("invalid %s\n", argv[0]);
        print_usage();
        exit(0);
    }

    if (pcap_file_name != NULL) {
        if (!open_pcap_packet_file(pcap_file_name)) {
            print_usage();
            exit(0);
        }
    }
}

int main(int argc, char *argv[])
{
    uint8_t slot_id_index;

    printf("%s version 0.1\n", "spdm_dump");

    process_args(argc, argv);

    if (!init_spdm_dump()) {
        close_pcap_packet_file();
        return 0;
    }
    if (!init_tdisp_dump()) {
        deinit_spdm_dump();
        close_pcap_packet_file();
        return 0;
    }
    if (!init_tsp_dump()) {
        deinit_tdisp_dump();
        deinit_spdm_dump();
        close_pcap_packet_file();
        return 0;
    }

    dump_pcap();

    deinit_tsp_dump();
    deinit_tdisp_dump();
    deinit_spdm_dump();

    close_pcap_packet_file();

    for (slot_id_index = 0; slot_id_index < LIBSPDM_ARRAY_SIZE(m_requester_cert_chain_data); slot_id_index++) {
        if (m_requester_cert_chain_data[slot_id_index] != NULL) {
            free(m_requester_cert_chain_data[slot_id_index]);
        }
    }
    for (slot_id_index = 0; slot_id_index < LIBSPDM_ARRAY_SIZE(m_responder_cert_chain_data); slot_id_index++) {
        if (m_responder_cert_chain_data[slot_id_index] != NULL) {
            free(m_responder_cert_chain_data[slot_id_index]);
        }
    }
    for (slot_id_index = 0; slot_id_index < LIBSPDM_ARRAY_SIZE(m_requester_cert_chain_buffer); slot_id_index++) {
        if (m_requester_cert_chain_buffer[slot_id_index] != NULL) {
            free(m_requester_cert_chain_buffer[slot_id_index]);
        }
    }
    for (slot_id_index = 0; slot_id_index < LIBSPDM_ARRAY_SIZE(m_responder_cert_chain_buffer); slot_id_index++) {
        if (m_responder_cert_chain_buffer[slot_id_index] != NULL) {
            free(m_responder_cert_chain_buffer[slot_id_index]);
        }
    }
    return 0;
}
