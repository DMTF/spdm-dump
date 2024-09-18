/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

#define TSP_CONFIGURATION_REPORT_BUFFER_MAX_SIZE 0x1000

void *m_tsp_configuration_report_buffer;
size_t m_tsp_configuration_report_buffer_size;
size_t m_cached_tsp_configuration_report_buffer_offset;

void dump_cxl_tsp_get_version(const void *buffer, size_t buffer_size)
{
    printf("GET_VERSION ");

    if (buffer_size < sizeof(cxl_tsp_get_target_tsp_version_req_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_cxl_tsp_get_version_rsp(const void *buffer, size_t buffer_size)
{
    const cxl_tsp_get_target_tsp_version_rsp_t *response;
    const cxl_tsp_version_number_t *version;
    size_t index;

    printf("GET_VERSION_RSP ");

    if (buffer_size < sizeof(cxl_tsp_get_target_tsp_version_rsp_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (buffer_size < sizeof(cxl_tsp_get_target_tsp_version_rsp_t) + 
                      response->version_number_entry_count * sizeof(cxl_tsp_version_number_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        version = (void *)((size_t)buffer + sizeof(cxl_tsp_get_target_tsp_version_rsp_t));
        printf("(");
        for (index = 0;
             index < response->version_number_entry_count;
             index++) {
            if (index != 0) {
                printf(", ");
            }
            printf("%d.%d",
                   (version[index] >> 4) & 0xF,
                   version[index] & 0xF);
        }
        printf(") ");
    }

    printf("\n");
}

void dump_cxl_tsp_get_capabilities(const void *buffer, size_t buffer_size)
{
    printf("GET_CAPABILITIES ");

    if (buffer_size < sizeof(cxl_tsp_get_target_capabilities_req_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_cxl_tsp_get_capabilities_rsp(const void *buffer, size_t buffer_size)
{
    const cxl_tsp_get_target_capabilities_rsp_t *response;

    printf("GET_CAPABILITIES_RSP ");

    if (buffer_size < sizeof(cxl_tsp_get_target_capabilities_rsp_t)) {
        printf("\n");
        return;
    }

    response = buffer;

    if (!m_param_quite_mode) {
        printf("(mem_enc_feat=0x%04x, ", response->memory_encryption_features_supported);
        printf("mem_enc_algo=0x%08x, ", response->memory_encryption_algorithms_supported);
        printf("mem_enc_num_rang=0x%04x, ", response->memory_encryption_number_of_range_based_keys);
        printf("te_cntl_feat=0x%04x, ", response->te_state_change_and_access_control_features_supported);
        printf("oob_te_gran=0x%08x, ", response->supported_explicit_oob_te_state_granularity);
        printf("ib_te_gran=0x%08x, ", response->supported_explicit_ib_te_state_granularity);
        printf("cfg_feat=0x%04x, ", response->configuration_features_supported);
        printf("num_ckid=0x%08x, ", response->number_of_ckids);
        printf("num_2nd_sess=0x%02x)", response->number_of_secondary_sessions);
    }

    printf("\n");
}

void dump_cxl_tsp_set_configuration(const void *buffer, size_t buffer_size)
{
    const cxl_tsp_set_target_configuration_req_t *request;
    size_t index;
    size_t sub_index;

    printf("SET_CONFIGURATION ");

    if (buffer_size < sizeof(cxl_tsp_set_target_configuration_req_t)) {
        printf("\n");
        return;
    }

    request = buffer;
    if (!m_param_quite_mode) {
        printf("(mem_enc_feat=0x%04x, ", request->memory_encryption_features_enable);
        printf("mem_enc_algo=0x%08x, ", request->memory_encryption_algorithm_select);
        printf("te_cntl_feat=0x%04x, ", request->te_state_change_and_access_control_features_enable);
        printf("oob_te_gran=0x%08x, ", request->explicit_oob_te_state_granularity);
        printf("cfg_feat=0x%04x, ", request->configuration_features_enable);
        printf("ckid_base=0x%08x, ", request->ckid_base);
        printf("num_ckid=0x%08x, ", request->number_of_ckids);
        printf("ib_te_gran=[");
        for (index = 0;
             index < LIBSPDM_ARRAY_SIZE(request->explicit_ib_te_state_granularity_entry);
             index++) {
            printf("0x%08x%08x-",
                (uint32_t)(request->explicit_ib_te_state_granularity_entry[index].te_state_granularity >> 32),
                (uint32_t)request->explicit_ib_te_state_granularity_entry[index].te_state_granularity);
            printf("0x%02x", request->explicit_ib_te_state_granularity_entry[index].length_index);
            if (index != LIBSPDM_ARRAY_SIZE(request->explicit_ib_te_state_granularity_entry) - 1) {
                printf(",");
            }
        }
        printf("], ");
        printf("\n  ");
        printf("cfg_valid=0x%04x, ", request->configuration_validity_flags);
        printf("2nd_sess_ckid=0x%02x, ", request->secondary_session_ckid_type);
        printf("2nd_sess_psk=[");
        for (index = 0;
             index < LIBSPDM_ARRAY_SIZE(request->secondary_session_psk_key_material);
             index++) {
            for (sub_index = 0;
                 sub_index < LIBSPDM_ARRAY_SIZE(request->secondary_session_psk_key_material[index].key_material);
                 sub_index++) {
                printf("%02x", request->secondary_session_psk_key_material[index].key_material[sub_index]);
            }
            if (index != LIBSPDM_ARRAY_SIZE(request->secondary_session_psk_key_material) - 1) {
                printf(",");
            }
        }
        printf("])");
    }
    printf("\n");
}

void dump_cxl_tsp_set_configuration_rsp(const void *buffer, size_t buffer_size)
{
    printf("SET_CAPABILITIES_RSP ");

    if (buffer_size < sizeof(cxl_tsp_set_target_configuration_rsp_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_cxl_tsp_get_configuration(const void *buffer, size_t buffer_size)
{
    printf("GET_CONFIGURATION ");

    if (buffer_size < sizeof(cxl_tsp_get_target_configuration_req_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_cxl_tsp_get_configuration_rsp(const void *buffer, size_t buffer_size)
{
    const cxl_tsp_get_target_configuration_rsp_t *response;
    size_t index;

    printf("GET_CONFIGURATION_RSP ");

    if (buffer_size < sizeof(cxl_tsp_get_target_configuration_rsp_t)) {
        printf("\n");
        return;
    }

    response = buffer;

    if (!m_param_quite_mode) {
        printf("(mem_enc_feat=0x%04x, ", response->memory_encryption_features_enabled);
        printf("mem_enc_algo=0x%08x, ", response->memory_encryption_algorithm_selected);
        printf("te_cntl_feat=0x%04x, ", response->te_state_change_and_access_control_features_enabled);
        printf("oob_te_gran=0x%08x, ", response->explicit_oob_te_state_granularity_enabled);
        printf("cfg_feat=0x%04x, ", response->configuration_features_enabled);
        printf("ckid_base=0x%08x, ", response->ckid_base);
        printf("num_ckid=0x%08x, ", response->number_of_ckids);
        printf("current_tsp_state=0x%02x, ", response->current_tsp_state);
        printf("ib_te_gran=[");
        for (index = 0;
             index < LIBSPDM_ARRAY_SIZE(response->explicit_ib_te_state_granularity_entry);
             index++) {
            printf("0x%08x%08x-",
                (uint32_t)(response->explicit_ib_te_state_granularity_entry[index].te_state_granularity >> 32),
                (uint32_t)response->explicit_ib_te_state_granularity_entry[index].te_state_granularity);
            printf("0x%02x", response->explicit_ib_te_state_granularity_entry[index].length_index);
            if (index != LIBSPDM_ARRAY_SIZE(response->explicit_ib_te_state_granularity_entry) - 1) {
                printf(",");
            }
        }
        printf("])");
    }

    printf("\n");
}

void dump_cxl_tsp_configuration_report (const void *buffer, size_t buffer_size)
{
    const cxl_tsp_target_configuration_report_t  *configuration_report;

    if (buffer_size < sizeof(cxl_tsp_target_configuration_report_t)) {
        return ;
    }

    configuration_report = buffer;
    printf("\n      ConfigurationReport(");
    printf("valid_field=%02x", configuration_report->valid_tsp_report_fields);
    printf(")");
}

void dump_cxl_tsp_get_configuration_report(const void *buffer, size_t buffer_size)
{
    const cxl_tsp_get_target_configuration_report_req_t *request;

    printf("GET_CONFIGURATION_REPORT ");

    if (buffer_size < sizeof(cxl_tsp_get_target_configuration_report_req_t)) {
        printf("\n");
        return;
    }

    request = buffer;
    if (!m_param_quite_mode) {
        printf("(offset=0x%04x, ", request->offset);
        printf("length=0x%04x)", request->length);
    }

    m_cached_tsp_configuration_report_buffer_offset = request->offset;
    printf("\n");
}

void dump_cxl_tsp_get_configuration_report_rsp(const void *buffer, size_t buffer_size)
{
    const cxl_tsp_get_target_configuration_report_rsp_t *response;

    printf("GET_CONFIGURATION_REPORT_RSP ");

    if (buffer_size < sizeof(cxl_tsp_get_target_configuration_report_rsp_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (!m_param_quite_mode) {
        printf("(port_len=0x%04x, ", response->portion_length);
        printf("rem_len=0x%04x)", response->remainder_length);
    }

    if (m_cached_tsp_configuration_report_buffer_offset +
        response->portion_length >
        TSP_CONFIGURATION_REPORT_BUFFER_MAX_SIZE) {
        printf(
            "TSP configuration_report is too larger. Please increase TSP_CONFIGURATION_REPORT_BUFFER_MAX_SIZE and rebuild.\n");
        exit(0);
    }
    memcpy((uint8_t *)m_tsp_configuration_report_buffer +
           m_cached_tsp_configuration_report_buffer_offset,
           (response + 1), response->portion_length);
    m_tsp_configuration_report_buffer_size = m_cached_tsp_configuration_report_buffer_offset +
                                             response->portion_length;

    if (response->remainder_length == 0) {
        dump_cxl_tsp_configuration_report (m_tsp_configuration_report_buffer, m_tsp_configuration_report_buffer_size);
    }
    printf("\n");
}

void dump_cxl_tsp_lock_configuration(const void *buffer, size_t buffer_size)
{
    printf("LOCK_CONFIGURATION ");

    if (buffer_size < sizeof(cxl_tsp_lock_target_configuration_req_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_cxl_tsp_lock_configuration_rsp(const void *buffer, size_t buffer_size)
{
    printf("LOCK_CAPABILITIES_RSP ");

    if (buffer_size < sizeof(cxl_tsp_lock_target_configuration_rsp_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_cxl_tsp_error(const void *buffer, size_t buffer_size)
{
    const cxl_tsp_error_rsp_t *response;

    printf("ERROR ");

    if (buffer_size < sizeof(cxl_tsp_error_rsp_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (!m_param_quite_mode) {
        printf("(err_code=0x%08x, err_data=0x%08x) ",
               response->error_code,
               response->error_data);
    }
    printf("\n");
}

dispatch_table_entry_t m_cxl_tsp_dispatch[] = {
    { CXL_TSP_OPCODE_GET_TARGET_TSP_VERSION, "GET_VERSION", dump_cxl_tsp_get_version },
    { CXL_TSP_OPCODE_GET_TARGET_CAPABILITIES, "GET_CAPABILITIES", dump_cxl_tsp_get_capabilities },
    { CXL_TSP_OPCODE_SET_TARGET_CONFIGURATION, "SET_CONFIGURATION", dump_cxl_tsp_set_configuration },
    { CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION, "GET_CONFIGURATION", dump_cxl_tsp_get_configuration },
    { CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_REPORT, "GET_CONFIGURATION_REPORT", dump_cxl_tsp_get_configuration_report },
    { CXL_TSP_OPCODE_LOCK_TARGET_CONFIGURATION, "LOCK_CONFIGURATION", dump_cxl_tsp_lock_configuration },

    { CXL_TSP_OPCODE_GET_TARGET_TSP_VERSION_RSP, "GET_VERSION_RSP", dump_cxl_tsp_get_version_rsp },
    { CXL_TSP_OPCODE_GET_TARGET_CAPABILITIES_RSP, "GET_CAPABILITIES_RSP", dump_cxl_tsp_get_capabilities_rsp },
    { CXL_TSP_OPCODE_SET_TARGET_CONFIGURATION_RSP, "SET_CONFIGURATION_RSP", dump_cxl_tsp_set_configuration_rsp },
    { CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_RSP, "GET_CONFIGURATION_RSP", dump_cxl_tsp_get_configuration_rsp },
    { CXL_TSP_OPCODE_GET_TARGET_CONFIGURATION_REPORT_RSP, "GET_CONFIGURATION_REPORT_RSP", dump_cxl_tsp_get_configuration_report_rsp },
    { CXL_TSP_OPCODE_LOCK_TARGET_CONFIGURATION_RSP, "LOCK_CONFIGURATION_RSP", dump_cxl_tsp_lock_configuration_rsp },
    { CXL_TSP_OPCODE_ERROR_RSP, "ERROR", dump_cxl_tsp_error },
};

void dump_cxl_tsp_message(const void *buffer, size_t buffer_size)
{
    const cxl_tsp_header_t *cxl_tsp_header;

    if (buffer_size < sizeof(cxl_tsp_header_t)) {
        printf("\n");
        return;
    }
    cxl_tsp_header = buffer;

    printf("CXL_TSP(0x%02x) ", cxl_tsp_header->op_code);

    dump_dispatch_message(m_cxl_tsp_dispatch,
                          LIBSPDM_ARRAY_SIZE(m_cxl_tsp_dispatch),
                          cxl_tsp_header->op_code, (uint8_t *)buffer,
                          buffer_size);
}

bool init_tsp_dump ()
{
    m_tsp_configuration_report_buffer = (void *)malloc(TSP_CONFIGURATION_REPORT_BUFFER_MAX_SIZE);
    if (m_tsp_configuration_report_buffer == NULL) {
        printf("!!!memory out of resources!!!\n");
        return false;
    }
    return true;
}

void deinit_tsp_dump ()
{
    free (m_tsp_configuration_report_buffer);
}
