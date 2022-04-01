/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

void dump_pldm_control_get_tid(const void *buffer, size_t buffer_size)
{
    const pldm_message_header_t *pldm_message_header;
    bool is_req;
    size_t header_size;

    pldm_message_header = buffer;
    is_req = ((pldm_message_header->instance_id & 0x80) != 0);
    printf("GetTID_%s ", is_req ? "req" : "rsp");

    header_size = sizeof(pldm_message_header_t);
    if (!is_req) {
        header_size += sizeof(pldm_message_response_header_t);
    }

    if (is_req) {
        /* request*/
        if (!m_param_quite_mode) {
            printf("() ");
        }
    } else {
        /* response*/
        if (buffer_size < header_size + 1) {
            printf("\n");
            return;
        }

        if (!m_param_quite_mode) {
            printf("(tid=0x%02x) ",
                   *((uint8_t *)buffer + header_size));
        }
    }

    printf("\n");
}

dispatch_table_entry_t m_pldm_control_dispatch[] = {
    { PLDM_CONTROL_DISCOVERY_COMMAND_SET_TID, "SetTID", NULL },
    { PLDM_CONTROL_DISCOVERY_COMMAND_GET_TID, "GetTID",
      dump_pldm_control_get_tid },
    { PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_VERSION, "GetPLDMVersion",
      NULL },
    { PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_TYPES, "GetPLDMTypes", NULL },
    { PLDM_CONTROL_DISCOVERY_COMMAND_GET_PLDM_COMMANDS, "GetPLDMCommands",
      NULL },
};

void dump_pldm_control(const void *buffer, size_t buffer_size)
{
    const pldm_message_header_t *pldm_message_header;

    printf("ControlDiscovery ");

    pldm_message_header = buffer;

    dump_dispatch_message(m_pldm_control_dispatch,
                          LIBSPDM_ARRAY_SIZE(m_pldm_control_dispatch),
                          pldm_message_header->pldm_command_code,
                          (uint8_t *)buffer, buffer_size);
}

dispatch_table_entry_t m_pldm_dispatch[] = {
    { PLDM_MESSAGE_TYPE_CONTROL_DISCOVERY, "ControlDiscovery",
      dump_pldm_control },
    { PLDM_MESSAGE_TYPE_SMBIOS, "SMBIOS", NULL },
    { PLDM_MESSAGE_TYPE_PLATFORM_MONITORING_CONTROL, "Platform", NULL },
    { PLDM_MESSAGE_TYPE_BIOS_CONTROL_CONFIGURATION, "BIOS", NULL },
    { PLDM_MESSAGE_TYPE_FRU_DATA, "FRU", NULL },
    { PLDM_MESSAGE_TYPE_FIRMWARE_UPDATE, "FirmwareUpdate", NULL },
    { PLDM_MESSAGE_TYPE_REDFISH_DEVICE_ENABLEMENT, "RedFish", NULL },
    { PLDM_MESSAGE_TYPE_OEM, "OEM", NULL },
};

void dump_pldm_message(const void *buffer, size_t buffer_size)
{
    const pldm_message_header_t *pldm_message_header;
    pldm_message_response_header_t *pldm_response_header;
    bool is_req;

    if (buffer_size < sizeof(pldm_message_header_t)) {
        printf("\n");
        return;
    }

    pldm_message_header = buffer;
    is_req = ((pldm_message_header->instance_id & 0x80) != 0);

    if (!is_req) {
        if (buffer_size <
            sizeof(pldm_message_header_t) +
            sizeof(pldm_message_response_header_t)) {
            printf("\n");
            return;
        }
    }

    if (is_req) {
        printf("PLDM(0x%02x, 0x%02x, 0x%02x) ",
               pldm_message_header->instance_id,
               pldm_message_header->pldm_type,
               pldm_message_header->pldm_command_code);
    } else {
        pldm_response_header = (void *)(pldm_message_header + 1);
        printf("PLDM(0x%02x, 0x%02x, 0x%02x, 0x%02x) ",
               pldm_message_header->instance_id,
               pldm_message_header->pldm_type,
               pldm_message_header->pldm_command_code,
               pldm_response_header->pldm_completion_code);
    }

    if (!m_param_quite_mode) {
        printf("(ID=%x, D=%x, Rq=%x) ",
               pldm_message_header->instance_id & 0x1F,
               ((pldm_message_header->instance_id & 0x40) != 0) ? 1 : 0,
               ((pldm_message_header->instance_id & 0x80) != 0) ? 1 :
               0);
    }

    dump_dispatch_message(m_pldm_dispatch, LIBSPDM_ARRAY_SIZE(m_pldm_dispatch),
                          pldm_message_header->pldm_type & 0x3F,
                          (uint8_t *)buffer, buffer_size);
}
