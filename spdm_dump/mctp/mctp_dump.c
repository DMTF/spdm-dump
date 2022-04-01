/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

dispatch_table_entry_t m_mctp_dispatch[] = {
    { MCTP_MESSAGE_TYPE_MCTP_CONTROL, "MctpControl", NULL },
    { MCTP_MESSAGE_TYPE_PLDM, "PLDM", dump_pldm_message },
    { MCTP_MESSAGE_TYPE_NCSI_CONTROL, "NCSI", NULL },
    { MCTP_MESSAGE_TYPE_ETHERNET, "Ethernet", NULL },
    { MCTP_MESSAGE_TYPE_NVME_MANAGEMENT, "NVMe", NULL },
    { MCTP_MESSAGE_TYPE_SPDM, "SPDM", dump_spdm_message },
    { MCTP_MESSAGE_TYPE_SECURED_MCTP, "SecuredSPDM",
      dump_secured_spdm_message },
    { MCTP_MESSAGE_TYPE_VENDOR_DEFINED_PCI, "VendorDefinedPci", NULL },
    { MCTP_MESSAGE_TYPE_VENDOR_DEFINED_IANA, "VendorDefinedIana", NULL },
};

void dump_mctp_message(const void *buffer, size_t buffer_size)
{
    mctp_message_header_t *mctp_message_header;
    size_t header_size;

    header_size = sizeof(mctp_message_header_t);
    if (buffer_size < header_size) {
        printf("\n");
        return;
    }
    mctp_message_header = (mctp_message_header_t *)((uint8_t *)buffer);

    printf("MCTP(%d) ", mctp_message_header->message_type);

    if (m_param_dump_vendor_app ||
        (mctp_message_header->message_type == MCTP_MESSAGE_TYPE_SPDM) ||
        (mctp_message_header->message_type ==
         MCTP_MESSAGE_TYPE_SECURED_MCTP)) {
        dump_dispatch_message(m_mctp_dispatch,
                              LIBSPDM_ARRAY_SIZE(m_mctp_dispatch),
                              mctp_message_header->message_type,
                              (uint8_t *)buffer + header_size,
                              buffer_size - header_size);

        if (m_param_dump_hex &&
            (mctp_message_header->message_type !=
             MCTP_MESSAGE_TYPE_SPDM) &&
            (mctp_message_header->message_type !=
             MCTP_MESSAGE_TYPE_SECURED_MCTP)) {
            printf("  MCTP message:\n");
            dump_hex(buffer, buffer_size);
        }
    } else {
        printf("\n");
    }
}

void dump_mctp_packet(const void *buffer, size_t buffer_size)
{
    size_t header_size;

    header_size = sizeof(mctp_header_t);
    if (buffer_size < header_size) {
        return;
    }

    dump_mctp_message((uint8_t *)buffer + header_size,
                      buffer_size - header_size);
}
