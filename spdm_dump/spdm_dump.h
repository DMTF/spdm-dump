/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#ifndef __SPDM_DUMP_H__
#define __SPDM_DUMP_H__

#include "base.h"
#include "industry_standard/spdm.h"
#include "industry_standard/spdm_secured_message.h"
#include "industry_standard/mctp.h"
#include "industry_standard/pldm.h"
#include "industry_standard/pcidoe.h"
#include "industry_standard/pci_idekm.h"
#include "industry_standard/pci_tdisp.h"
#include "industry_standard/cxl_idekm.h"
#include "industry_standard/cxl_tsp.h"
#include "industry_standard/pcap.h"
#include "industry_standard/link_type_ex.h"

#include "internal/libspdm_common_lib.h"
#include "internal/libspdm_secured_message_lib.h"
#include "library/spdm_crypt_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"

#include "hal/library/memlib.h"
#include "hal/library/debuglib.h"

#include "os_include.h"
#include <stddef.h>
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

typedef void (*dump_message_func)(const void *buffer, size_t buffer_size);

typedef struct {
    uint32_t id;
    char *name;
    dump_message_func dump_func;
} dispatch_table_entry_t;

dispatch_table_entry_t *
get_dispatch_entry_by_id(dispatch_table_entry_t *dispatch_table,
                         size_t dispatch_table_count, uint32_t id);

void dump_dispatch_message(dispatch_table_entry_t *dispatch_table,
                           size_t dispatch_table_count, uint32_t id,
                           const void *buffer, size_t buffer_size);

typedef struct {
    uint32_t value;
    char *name;
} value_string_entry_t;

void dump_entry_flags_all(const value_string_entry_t *entry_table,
                          size_t entry_table_count, uint32_t flags);

void dump_entry_flags(const value_string_entry_t *entry_table,
                      size_t entry_table_count, uint32_t flags);

void dump_entry_value(const value_string_entry_t *entry_table,
                      size_t entry_table_count, uint32_t value);

bool init_spdm_dump(void);

void deinit_spdm_dump(void);

bool open_pcap_packet_file(const char *pcap_file_name);

void close_pcap_packet_file(void);

void dump_pcap(void);

uint32_t get_data_link_type(void);

uint32_t get_max_packet_length(void);

void dump_hex_str(const uint8_t *data, size_t size);

void dump_data(const uint8_t *data, size_t size);

void dump_hex(const uint8_t *data, size_t size);

void dump_mctp_packet(const void *buffer, size_t buffer_size);

void dump_pci_doe_packet(const void *buffer, size_t buffer_size);

void dump_mctp_message(const void *buffer, size_t buffer_size);

void dump_spdm_message(const void *buffer, size_t buffer_size);

void dump_secured_spdm_message(const void *buffer, size_t buffer_size);

void dump_spdm_opaque_data(uint8_t spdm_version, const uint8_t *opaque_data,
                           uint16_t opaque_length);

void dump_pldm_message(const void *buffer, size_t buffer_size);

void dump_pci_doe_discovery_message(const void *buffer, size_t buffer_size);

void dump_spdm_vendor_pci(const void *buffer, size_t buffer_size);

void dump_pci_ide_km_message(const void *buffer, size_t buffer_size);

void dump_pci_tdisp_message(const void *buffer, size_t buffer_size);

void dump_cxl_ide_km_message(const void *buffer, size_t buffer_size);

void dump_cxl_tsp_message(const void *buffer, size_t buffer_size);

bool init_tdisp_dump(void);

void deinit_tdisp_dump(void);

bool init_tsp_dump(void);

void deinit_tsp_dump(void);

void spdm_dump_set_session_info_use_psk (void *spdm_session_info, bool use_psk);

void spdm_dump_set_session_info_mut_auth_requested (void *spdm_session_info,
                                                    uint8_t mut_auth_requested);

libspdm_return_t spdm_dump_session_data_provision(void *spdm_context,
                                               uint32_t session_id,
                                               bool need_mut_auth,
                                               bool is_requester);

libspdm_return_t spdm_dump_session_data_check(void *spdm_context,
                                           uint32_t session_id,
                                           bool is_requester);

bool hex_string_to_buffer(const char *hex_string, void **buffer,
                          size_t *buffer_size);

bool read_input_file(const char *file_name, void **file_data,
                     size_t *file_size);

bool write_output_file(const char *file_name, const void *file_data,
                       size_t file_size);

bool open_output_file(const char *file_name);

extern bool m_param_quite_mode;
extern bool m_param_all_mode;
extern bool m_param_dump_vendor_app;
extern bool m_param_dump_hex;

#define CERT_CHAIN_FORMAT_SPDM 0
#define CERT_CHAIN_FORMAT_RAW 1
extern uint32_t m_cert_chain_format;
extern char *m_param_out_rsp_cert_chain_file_name[SPDM_MAX_SLOT_COUNT];
extern char *m_param_out_rsq_cert_chain_file_name[SPDM_MAX_SLOT_COUNT];
extern void *m_requester_cert_chain_data[SPDM_MAX_SLOT_COUNT+1];
extern size_t m_requester_cert_chain_data_size[SPDM_MAX_SLOT_COUNT+1];
extern void *m_responder_cert_chain_data[SPDM_MAX_SLOT_COUNT+1];
extern size_t m_responder_cert_chain_data_size[SPDM_MAX_SLOT_COUNT+1];
extern void *m_requester_cert_chain_buffer[SPDM_MAX_SLOT_COUNT+1];
extern size_t m_requester_cert_chain_buffer_size[SPDM_MAX_SLOT_COUNT+1];
extern void *m_responder_cert_chain_buffer[SPDM_MAX_SLOT_COUNT+1];
extern size_t m_responder_cert_chain_buffer_size[SPDM_MAX_SLOT_COUNT+1];
extern void *m_dhe_secret_buffer[LIBSPDM_MAX_SESSION_COUNT];
extern size_t m_dhe_secret_buffer_size[LIBSPDM_MAX_SESSION_COUNT];
extern void *m_kem_secret_buffer[LIBSPDM_MAX_SESSION_COUNT];
extern size_t m_kem_secret_buffer_size[LIBSPDM_MAX_SESSION_COUNT];
extern void *m_psk_buffer[LIBSPDM_MAX_SESSION_COUNT];
extern size_t m_psk_buffer_size[LIBSPDM_MAX_SESSION_COUNT];

/*current used key index, index++ when finish command dump complete*/
extern uint8_t m_dhe_secret_buffer_count;
extern uint8_t m_kem_secret_buffer_count;
extern uint8_t m_psk_secret_buffer_count;

extern uint8_t m_responder_cert_chain_slot_id;
extern uint8_t m_requester_cert_chain_slot_id;

#define LIBSPDM_MAX_MEASUREMENT_EXTENSION_LOG_SIZE 0x1000

#endif
