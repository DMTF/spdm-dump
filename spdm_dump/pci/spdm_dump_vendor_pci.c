/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
**/

#include "spdm_dump.h"

dispatch_table_entry_t m_spdm_pci_protocol_dispatch[] = {
    { PCI_PROTOCAL_ID_IDE_KM, "IDE_KM", dump_pci_ide_km_message },
};

#pragma pack(1)

typedef struct {
    uint16_t standard_id;
    uint8_t len;
    uint16_t vendor_id;
    uint16_t payload_length;
    pci_protocol_header_t pci_protocol;
} spdm_vendor_defined_pci_header_t;

#pragma pack()

void dump_spdm_vendor_pci(IN void *buffer, IN uintn buffer_size)
{
    spdm_vendor_defined_pci_header_t *vendor_defined_pci_header;

    printf("PCI ");

    if (buffer_size < sizeof(spdm_vendor_defined_pci_header_t)) {
        printf("\n");
        return;
    }
    vendor_defined_pci_header = buffer;

    if (!m_param_quite_mode) {
        printf("(vendor_id=0x%04x) ",
               vendor_defined_pci_header->vendor_id);
    }

    if (vendor_defined_pci_header->len !=
        sizeof(vendor_defined_pci_header->vendor_id)) {
        printf("\n");
        return;
    }
    if (vendor_defined_pci_header->vendor_id != SPDM_VENDOR_ID_PCISIG) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("(ProtID=0x%02x) ",
               vendor_defined_pci_header->pci_protocol.protocol_id);
    }

    if (vendor_defined_pci_header->payload_length <
        sizeof(pci_protocol_header_t)) {
        printf("\n");
        return;
    }
    if (vendor_defined_pci_header->payload_length >
        buffer_size - (OFFSET_OF(spdm_vendor_defined_pci_header_t,
                     pci_protocol))) {
        printf("\n");
        return;
    }

    dump_dispatch_message(
        m_spdm_pci_protocol_dispatch,
        ARRAY_SIZE(m_spdm_pci_protocol_dispatch),
        vendor_defined_pci_header->pci_protocol.protocol_id,
        (uint8_t *)buffer + sizeof(spdm_vendor_defined_pci_header_t),
        vendor_defined_pci_header->payload_length -
            sizeof(pci_protocol_header_t));

    if (m_param_dump_hex) {
        printf("  PCI Vendor message:\n");
        dump_hex(buffer, buffer_size);
    }
}
