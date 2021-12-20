/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
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
#include "industry_standard/pcap.h"
#include "industry_standard/link_type_ex.h"

#include "library/spdm_common_lib.h"
#include "library/spdm_transport_mctp_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"

#include "os_include.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

typedef void (*dump_message_func)(IN void *buffer, IN uintn buffer_size);

typedef struct {
    uint32_t id;
    char *name;
    dump_message_func dump_func;
} dispatch_table_entry_t;

dispatch_table_entry_t *
get_dispatch_entry_by_id(IN dispatch_table_entry_t *dispatch_table,
             IN uintn dispatch_table_count, IN uint32_t id);

void dump_dispatch_message(IN dispatch_table_entry_t *dispatch_table,
               IN uintn dispatch_table_count, IN uint32_t id,
               IN void *buffer, IN uintn buffer_size);

typedef struct {
    uint32_t value;
    char *name;
} value_string_entry_t;

void dump_entry_flags_all(IN value_string_entry_t *entry_table,
              IN uintn entry_table_count, IN uint32_t flags);

void dump_entry_flags(IN value_string_entry_t *entry_table,
              IN uintn entry_table_count, IN uint32_t flags);

void dump_entry_value(IN value_string_entry_t *entry_table,
              IN uintn entry_table_count, IN uint32_t value);

boolean init_spdm_dump(void);

void deinit_spdm_dump(void);

boolean open_pcap_packet_file(IN char *pcap_file_name);

void close_pcap_packet_file(void);

void dump_pcap(void);

uint32_t get_data_link_type(void);

uint32_t get_max_packet_length(void);

void dump_hex_str(IN uint8_t *data, IN uintn size);

void dump_data(IN uint8_t *data, IN uintn size);

void dump_hex(IN uint8_t *data, IN uintn size);

void dump_mctp_packet(IN void *buffer, IN uintn buffer_size);

void dump_pci_doe_packet(IN void *buffer, IN uintn buffer_size);

void dump_mctp_message(IN void *buffer, IN uintn buffer_size);

void dump_spdm_message(IN void *buffer, IN uintn buffer_size);

void dump_secured_spdm_message(IN void *buffer, IN uintn buffer_size);

void dump_spdm_opaque_data(IN uint8_t *opaque_data, IN uint16_t opaque_length);

void dump_pldm_message(IN void *buffer, IN uintn buffer_size);

void dump_pci_doe_discovery_message(IN void *buffer, IN uintn buffer_size);

void dump_spdm_vendor_pci(IN void *buffer, IN uintn buffer_size);

void dump_pci_ide_km_message(IN void *buffer, IN uintn buffer_size);

return_status spdm_dump_session_data_provision(IN void *spdm_context,
                           IN uint32_t session_id,
                           IN boolean need_mut_auth,
                           IN boolean is_requester);

return_status spdm_dump_session_data_check(IN void *spdm_context,
                       IN uint32_t session_id,
                       IN boolean is_requester);

boolean hex_string_to_buffer(IN char *hex_string, OUT void **buffer,
                 OUT uintn *buffer_size);

boolean read_input_file(IN char *file_name, OUT void **file_data,
            OUT uintn *file_size);

boolean write_output_file(IN char *file_name, IN void *file_data,
              IN uintn file_size);

boolean open_output_file(IN char *file_name);

extern boolean m_param_quite_mode;
extern boolean m_param_all_mode;
extern boolean m_param_dump_vendor_app;
extern boolean m_param_dump_hex;
extern char *m_param_out_rsp_cert_chain_file_name;
extern char *m_param_out_rsq_cert_chain_file_name;

extern void *m_requester_cert_chain_buffer;
extern uintn m_requester_cert_chain_buffer_size;
extern void *m_responder_cert_chain_buffer;
extern uintn m_responder_cert_chain_buffer_size;
extern void *m_dhe_secret_buffer;
extern uintn m_dhe_secret_buffer_size;
extern void *m_psk_buffer;
extern uintn m_psk_buffer_size;

#endif