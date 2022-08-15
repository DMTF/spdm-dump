/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

#define TDISP_INTERFACE_REPORT_BUFFER_MAX_SIZE 0x1000

void *m_tdisp_interface_report_buffer;
size_t m_tdisp_interface_report_buffer_size;
size_t m_cached_tdisp_interface_report_buffer_offset;

void dump_pci_tdisp_interface_id(const pci_tdisp_interface_id_t *interface_id)
{
    printf("(%08x) ", interface_id->function_id);
}

void dump_pci_tdisp_interface_report (const void *buffer, size_t buffer_size)
{
    const pci_tdisp_device_interface_report_struct_t  *interface_report;
    const pci_tdisp_mmio_range_t *mmio_range;
    const uint32_t *device_specific_info_len_ptr;
    const uint8_t *device_specific_info_ptr;
    uint32_t index;

    if (buffer_size < sizeof(pci_tdisp_device_interface_report_struct_t)) {
        return ;
    }

    interface_report = buffer;
    if (buffer_size < sizeof(pci_tdisp_device_interface_report_struct_t) +
                      sizeof(pci_tdisp_mmio_range_t) * interface_report->mmio_range_count +
                      sizeof(uint32_t)) {
        return ;
    }
    mmio_range = (void *)((uint8_t *)buffer + sizeof(pci_tdisp_device_interface_report_struct_t));
    device_specific_info_len_ptr = (void *)(mmio_range + interface_report->mmio_range_count);
    device_specific_info_ptr = (void *)(device_specific_info_len_ptr + 1);
    if (buffer_size < sizeof(pci_tdisp_device_interface_report_struct_t) +
                      sizeof(pci_tdisp_mmio_range_t) * interface_report->mmio_range_count +
                      sizeof(uint32_t) + *device_specific_info_len_ptr) {
        return ;
    }
    
    printf("\n      InterfaceReport(");
    printf("if_info=%04x, ", interface_report->interface_info);
    printf("msix_ctrl=%04x, ", interface_report->msi_x_message_control);
    printf("lnr_ctrl=%04x, ", interface_report->lnr_control);
    printf("tph_ctrl=%08x, ", interface_report->tph_control);
    printf("mmio_count=%08x, ", interface_report->mmio_range_count);
    for (index = 0; index < interface_report->mmio_range_count; index++) {
        printf("\n        mmio_range(%d)=", index);
        printf("(first=0x%08x%08x, ", (uint32_t)(mmio_range[index].first_page >> 32), (uint32_t)mmio_range[index].first_page);
        printf("num_pg=0x%08x, ", mmio_range[index].number_of_pages);
        printf("attr=0x%04x, ", mmio_range[index].range_attributes);
        printf("rang_id=0x%04x)", mmio_range[index].range_id);
    }
    printf("\n        dev_info(len=%08x, data=(", *device_specific_info_len_ptr);
    for (index = 0; index < *device_specific_info_len_ptr; index++) {
        printf("%02x, ", device_specific_info_ptr[index]);
    }
    printf(")))");
}

void dump_pci_tdisp_get_version(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_get_version_request_t *request;

    printf("GET_VERSION ");

    if (buffer_size < sizeof(pci_tdisp_get_version_request_t)) {
        printf("\n");
        return;
    }

    request = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&request->header.interface_id);
    }
    printf("\n");
}

void dump_pci_tdisp_version(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_version_response_t *response;
    const pci_tdisp_version_number_t *version;
    size_t index;

    printf("VERSION ");

    if (buffer_size < sizeof(pci_tdisp_version_response_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (buffer_size < sizeof(pci_tdisp_version_response_t) + 
                      response->version_num_count * sizeof(pci_tdisp_version_number_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&response->header.interface_id);
        version = (void *)((size_t)buffer + sizeof(pci_tdisp_version_response_t));
        printf("(");
        for (index = 0;
             index < response->version_num_count;
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

void dump_pci_tdisp_get_capabilities(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_get_capabilities_request_t *request;

    printf("GET_CAPABILITIES ");

    if (buffer_size < sizeof(pci_tdisp_get_capabilities_request_t)) {
        printf("\n");
        return;
    }

    request = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&request->header.interface_id);
        printf("(tsm_caps=0x%08x) ", request->req_caps.tsm_caps);
    }
    printf("\n");
}

void dump_pci_tdisp_capabilities(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_capabilities_response_t *response;
    int32_t index;

    printf("CAPABILITIES ");

    if (buffer_size < sizeof(pci_tdisp_capabilities_response_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&response->header.interface_id);
        printf("(dsm_caps=0x%08x, ", response->rsp_caps.dsm_caps);
        printf("msg_cap=[");
        for (index = sizeof(response->rsp_caps.req_msg_supported) - 1;
             index >= 0;
             index--) {
            printf("%02x", response->rsp_caps.req_msg_supported[index]);
        }
        printf("], ");
        printf("lock_flags=0x%04x, ", response->rsp_caps.lock_interface_flags_supported);
        printf("addr_width=0x%02x, ", response->rsp_caps.dev_addr_width);
        printf("req_this=0x%02x, ", response->rsp_caps.num_req_this);
        printf("req_all=0x%02x)", response->rsp_caps.num_req_all);
    }
    printf("\n");
}

void dump_pci_tdisp_lock_interface_req(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_lock_interface_request_t *request;

    printf("LOCK_INTERFACE_REQ ");

    if (buffer_size < sizeof(pci_tdisp_lock_interface_request_t)) {
        printf("\n");
        return;
    }

    request = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&request->header.interface_id);
        printf("(flags=0x%04x, ", request->lock_interface_param.flags);
        printf("default_stream=0x%02x, ", request->lock_interface_param.default_stream_id);
        printf("mmio_offset=0x%08x%08x, ",
            (uint32_t)(request->lock_interface_param.mmio_reporting_offset >> 32),
            (uint32_t)request->lock_interface_param.mmio_reporting_offset);
        printf("bind_p2p_mask=0x%08x%08x)",
            (uint32_t)(request->lock_interface_param.bind_p2p_address_mask >> 32),
            (uint32_t)request->lock_interface_param.bind_p2p_address_mask);
    }
    printf("\n");
}

void dump_pci_tdisp_lock_interface_rsp(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_lock_interface_response_t *response;
    uint32_t index;

    printf("LOCK_INTERFACE_RSP ");

    if (buffer_size < sizeof(pci_tdisp_lock_interface_response_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&response->header.interface_id);
        printf("(nonce=");
        for (index = 0;
             index < sizeof(response->start_interface_nonce);
             index++) {
            printf("%02x", response->start_interface_nonce[index]);
        }
        printf(")");
    }
    printf("\n");
}

void dump_pci_tdisp_get_device_interface_report(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_get_device_interface_report_request_t *request;

    printf("GET_DEVICE_INTERFACE_REPORT ");

    if (buffer_size < sizeof(pci_tdisp_get_device_interface_report_request_t)) {
        printf("\n");
        return;
    }

    request = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&request->header.interface_id);
        printf("(offset=0x%04x, ", request->offset);
        printf("length=0x%04x)", request->length);
    }

    m_cached_tdisp_interface_report_buffer_offset = request->offset;
    printf("\n");
}

void dump_pci_tdisp_device_interface_report(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_device_interface_report_response_t *response;

    printf("DEVICE_INTERFACE_REPORT ");

    if (buffer_size < sizeof(pci_tdisp_device_interface_report_response_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&response->header.interface_id);
        printf("(port_len=0x%04x, ", response->portion_length);
        printf("rem_len=0x%04x)", response->remainder_length);
    }

    if (m_cached_tdisp_interface_report_buffer_offset +
        response->portion_length >
        TDISP_INTERFACE_REPORT_BUFFER_MAX_SIZE) {
        printf(
            "TDISP interface_report is too larger. Please increase TDISP_INTERFACE_REPORT_BUFFER_MAX_SIZE and rebuild.\n");
        exit(0);
    }
    memcpy((uint8_t *)m_tdisp_interface_report_buffer +
           m_cached_tdisp_interface_report_buffer_offset,
           (response + 1), response->portion_length);
    m_tdisp_interface_report_buffer_size = m_cached_tdisp_interface_report_buffer_offset +
                                           response->portion_length;

    if (response->remainder_length == 0) {
        dump_pci_tdisp_interface_report (m_tdisp_interface_report_buffer, m_tdisp_interface_report_buffer_size);
    }
    printf("\n");
}

void dump_pci_tdisp_get_device_interface_state(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_get_device_interface_state_request_t *request;

    printf("GET_DEVICE_INTERFACE_STATE ");

    if (buffer_size < sizeof(pci_tdisp_get_device_interface_state_request_t)) {
        printf("\n");
        return;
    }

    request = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&request->header.interface_id);
    }

    printf("\n");
}

void dump_pci_tdisp_device_interface_state(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_device_interface_state_response_t *response;

    printf("DEVICE_INTERFACE_STATE ");

    if (buffer_size < sizeof(pci_tdisp_device_interface_state_response_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&response->header.interface_id);
        printf("(tdi_state=0x%02x)", response->tdi_state);
    }
    printf("\n");
}

void dump_pci_tdisp_start_interface_req(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_start_interface_request_t *request;
    uint32_t index;

    printf("START_INTERFACE_REQ ");

    if (buffer_size < sizeof(pci_tdisp_start_interface_request_t)) {
        printf("\n");
        return;
    }

    request = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&request->header.interface_id);
        printf("(nonce=");
        for (index = 0;
             index < sizeof(request->start_interface_nonce);
             index++) {
            printf("%02x", request->start_interface_nonce[index]);
        }
        printf(")");
    }

    printf("\n");
}

void dump_pci_tdisp_start_interface_rsp(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_start_interface_response_t *response;

    printf("START_INTERFACE_RSP ");

    if (buffer_size < sizeof(pci_tdisp_start_interface_response_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&response->header.interface_id);
    }
    printf("\n");
}

void dump_pci_tdisp_stop_interface_req(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_stop_interface_request_t *request;

    printf("STOP_INTERFACE_REQ ");

    if (buffer_size < sizeof(pci_tdisp_stop_interface_request_t)) {
        printf("\n");
        return;
    }

    request = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&request->header.interface_id);
    }

    printf("\n");
}

void dump_pci_tdisp_stop_interface_rsp(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_stop_interface_response_t *response;

    printf("STOP_INTERFACE_RSP ");

    if (buffer_size < sizeof(pci_tdisp_stop_interface_response_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&response->header.interface_id);
    }
    printf("\n");
}

void dump_pci_tdisp_error(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_error_response_t *response;

    printf("ERROR ");

    if (buffer_size < sizeof(pci_tdisp_error_response_t)) {
        printf("\n");
        return;
    }

    response = buffer;
    if (!m_param_quite_mode) {
        dump_pci_tdisp_interface_id (&response->header.interface_id);
        printf("(err_code=0x%08x, err_data=0x%08x) ",
               response->error_code,
               response->error_data);
    }
    printf("\n");
}

dispatch_table_entry_t m_pci_tdisp_dispatch[] = {
    { PCI_TDISP_VERSION, "VERSION", dump_pci_tdisp_version },
    { PCI_TDISP_CAPABILITIES, "CAPABILITIES", dump_pci_tdisp_capabilities },
    { PCI_TDISP_LOCK_INTERFACE_RSP, "LOCK_INTERFACE_RSP", dump_pci_tdisp_lock_interface_rsp },
    { PCI_TDISP_DEVICE_INTERFACE_REPORT, "DEVICE_INTERFACE_REPORT", dump_pci_tdisp_device_interface_report },
    { PCI_TDISP_DEVICE_INTERFACE_STATE, "DEVICE_INTERFACE_STATE", dump_pci_tdisp_device_interface_state },
    { PCI_TDISP_START_INTERFACE_RSP, "START_INTERFACE_RSP", dump_pci_tdisp_start_interface_rsp },
    { PCI_TDISP_STOP_INTERFACE_RSP, "STOP_INTERFACE_RSP", dump_pci_tdisp_stop_interface_rsp },
    { PCI_TDISP_BIND_P2P_STREAM_RSP, "BIND_P2P_STREAM_RSP", NULL },
    { PCI_TDISP_UNBIND_P2P_STREAM_RSP, "UNBIND_P2P_STREAM_RSP", NULL },
    { PCI_TDISP_SET_MMIO_ATTRIBUTE_RSP, "SET_MMIO_ATTRIBUTE_RSP", NULL },
    { PCI_TDISP_VDM_RSP, "VDM_RSP", NULL },
    { PCI_TDISP_ERROR, "ERROR", dump_pci_tdisp_error },

    { PCI_TDISP_GET_VERSION, "GET_VERSION", dump_pci_tdisp_get_version },
    { PCI_TDISP_GET_CAPABILITIES, "GET_CAPABILITIES", dump_pci_tdisp_get_capabilities },
    { PCI_TDISP_LOCK_INTERFACE_REQ, "LOCK_INTERFACE_REQ", dump_pci_tdisp_lock_interface_req },
    { PCI_TDISP_GET_DEVICE_INTERFACE_REPORT, "GET_DEVICE_INTERFACE_REPORT", dump_pci_tdisp_get_device_interface_report },
    { PCI_TDISP_GET_DEVICE_INTERFACE_STATE, "GET_DEVICE_INTERFACE_STATE", dump_pci_tdisp_get_device_interface_state },
    { PCI_TDISP_START_INTERFACE_REQ, "START_INTERFACE_REQ", dump_pci_tdisp_start_interface_req },
    { PCI_TDISP_STOP_INTERFACE_REQ, "STOP_INTERFACE_REQ", dump_pci_tdisp_stop_interface_req },
    { PCI_TDISP_BIND_P2P_STREAM_REQ, "BIND_P2P_STREAM_REQ", NULL },
    { PCI_TDISP_UNBIND_P2P_STREAM_REQ, "UNBIND_P2P_STREAM_REQ", NULL },
    { PCI_TDISP_SET_MMIO_ATTRIBUTE_REQ, "SET_MMIO_ATTRIBUTE_REQ", NULL },
    { PCI_TDISP_VDM_REQ, "VDM_REQ", NULL },
};

void dump_pci_tdisp_message(const void *buffer, size_t buffer_size)
{
    const pci_tdisp_header_t *pci_tdisp_header;

    if (buffer_size < sizeof(pci_tdisp_header_t)) {
        printf("\n");
        return;
    }
    pci_tdisp_header = buffer;

    printf("TDISP(0x%02x) ", pci_tdisp_header->message_type);

    dump_dispatch_message(m_pci_tdisp_dispatch,
                          LIBSPDM_ARRAY_SIZE(m_pci_tdisp_dispatch),
                          pci_tdisp_header->message_type, (uint8_t *)buffer,
                          buffer_size);
}

bool init_tdisp_dump ()
{
    m_tdisp_interface_report_buffer = (void *)malloc(TDISP_INTERFACE_REPORT_BUFFER_MAX_SIZE);
    if (m_tdisp_interface_report_buffer == NULL) {
        printf("!!!memory out of resources!!!\n");
        return false;
    }
    return true;
}

void deinit_tdisp_dump ()
{
    free (m_tdisp_interface_report_buffer);
}
