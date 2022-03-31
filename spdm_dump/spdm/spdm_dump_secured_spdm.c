/**
 *  Copyright Notice:
 *  Copyright 2021 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

extern void *m_spdm_dec_message_buffer;
extern void *m_spdm_context;
extern void *m_current_session_info;
extern uint32_t m_current_session_id;
extern bool m_decrypted;
extern uint8_t m_spdm_other_params_support;

void dump_spdm_opaque_version_selection(const void *buffer, size_t buffer_size)
{
    const secured_message_opaque_element_version_selection_t *version_selection;

    if (buffer_size <
        sizeof(secured_message_opaque_element_version_selection_t)) {
        return;
    }

    version_selection = buffer;

    printf("VERSION_SELECTION ");

    printf("(%d.%d.%d.%d) ",
           (version_selection->selected_version >> 12) & 0xF,
           (version_selection->selected_version >> 8) & 0xF,
           (version_selection->selected_version >> 4) & 0xF,
           version_selection->selected_version & 0xF);
}

void dump_spdm_opaque_supported_version(const void *buffer, size_t buffer_size)
{
    const secured_message_opaque_element_supported_version_t *supported_version;
    spdm_version_number_t *spdm_version_number;
    size_t index;

    if (buffer_size <
        sizeof(secured_message_opaque_element_supported_version_t)) {
        return;
    }

    supported_version = buffer;
    if (buffer_size <
        sizeof(secured_message_opaque_element_supported_version_t) +
        supported_version->version_count *
        sizeof(spdm_version_number_t)) {
        return;
    }

    printf("SUPPORTED_VERSION ");

    spdm_version_number = (void *)(supported_version + 1);
    printf("(");
    for (index = 0; index < supported_version->version_count; index++) {
        if (index != 0) {
            printf(", ");
        }
        printf("%d.%d.%d.%d",
               (spdm_version_number[index] >> 12) & 0xF,
               (spdm_version_number[index] >> 8) & 0xF,
               (spdm_version_number[index] >> 4) & 0xF,
               spdm_version_number[index] & 0xF);
        printf(") ");
    }
}

dispatch_table_entry_t m_spdm_opaque_dispatch[] = {
    { SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION,
      "VERSION_SELECTION", dump_spdm_opaque_version_selection },
    { SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION,
      "SUPPORTED_VERSION", dump_spdm_opaque_supported_version },
};

void dump_spdm_opaque_data(uint8_t spdm_version, const uint8_t *opaque_data, uint16_t opaque_length)
{
    secured_message_general_opaque_data_table_header_t
    *secured_message_opaque_data_table;
    spdm_general_opaque_data_table_header_t
    *spdm_opaque_data_table_header;
    uint8_t total_elements;
    secured_message_opaque_element_table_header_t
    *secured_message_element_table;
    secured_message_opaque_element_header_t *secured_message_element;
    size_t end_of_element_table;
    size_t end_of_opaque_data;
    size_t index;
    char *ch;

    end_of_opaque_data = (size_t)opaque_data + opaque_length;

    if ((spdm_version >= SPDM_MESSAGE_VERSION_12) &&
        ((m_spdm_other_params_support & SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_MASK) ==
         SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1)) {
        if (opaque_length <
            sizeof(spdm_general_opaque_data_table_header_t)) {
            return;
        }

        spdm_opaque_data_table_header = (void *)opaque_data;

        printf("\n      SpdmOpaqueDataHeader(TotalElem=0x%02x)",
               spdm_opaque_data_table_header->total_elements);

        secured_message_element_table =
            (void *)(spdm_opaque_data_table_header + 1);
        total_elements = spdm_opaque_data_table_header->total_elements;
    } else {
        if (opaque_length <
            sizeof(secured_message_general_opaque_data_table_header_t)) {
            return;
        }

        secured_message_opaque_data_table = (void *)opaque_data;
        if (secured_message_opaque_data_table->spec_id !=
            SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID) {
            return;
        }

        ch = (void *)&secured_message_opaque_data_table->spec_id;
        printf(
            "\n      SecuredMessageOpaqueDataHeader(spec_id=0x%08x(%c%c%c%c), Ver=0x%02x, TotalElem=0x%02x)",
            secured_message_opaque_data_table->spec_id, ch[3], ch[2], ch[1],
            ch[0], secured_message_opaque_data_table->opaque_version,
            secured_message_opaque_data_table->total_elements);

        secured_message_element_table =
            (void *)(secured_message_opaque_data_table + 1);
        total_elements = secured_message_opaque_data_table->total_elements;
    }
    for (index = 0;
         index < total_elements;
         index++) {
        if ((size_t)secured_message_element_table +
            sizeof(secured_message_opaque_element_table_header_t) >
            end_of_opaque_data) {
            break;
        }
        if (secured_message_element_table->id !=
            SPDM_REGISTRY_ID_DMTF) {
            break;
        }
        if (secured_message_element_table->vendor_len != 0) {
            break;
        }
        end_of_element_table =
            (size_t)secured_message_element_table +
            sizeof(secured_message_opaque_element_table_header_t) +
            secured_message_element_table->opaque_element_data_len;
        if (end_of_element_table > end_of_opaque_data) {
            break;
        }
        printf("\n      SecuredMessageOpaqueElement_%d(id=0x%02x, len=0x%04x) ",
               (uint32_t)index, secured_message_element_table->id,
               secured_message_element_table->opaque_element_data_len);

        if (secured_message_element_table->opaque_element_data_len <
            sizeof(secured_message_opaque_element_header_t)) {
            break;
        }
        secured_message_element =
            (void *)(secured_message_element_table + 1);
        printf("Element(Ver=0x%02x, id=0x%02x) ",
               secured_message_element->sm_data_version,
               secured_message_element->sm_data_id);

        dump_dispatch_message(
            m_spdm_opaque_dispatch,
            LIBSPDM_ARRAY_SIZE(m_spdm_opaque_dispatch),
            secured_message_element->sm_data_id,
            (uint8_t *)secured_message_element,
            secured_message_element_table->opaque_element_data_len);

        secured_message_element_table = (void *)end_of_element_table;
    }
}

dispatch_table_entry_t m_secured_spdm_dispatch[] = {
    { LINKTYPE_MCTP, "", dump_mctp_message },
    { LINKTYPE_PCI_DOE, "", dump_spdm_message },
};

void dump_secured_spdm_message(const void *buffer, size_t buffer_size)
{
    const spdm_secured_message_a_data_header1_t *record_header1;
    uint16_t sequence_num;
    size_t sequence_num_size;
    libspdm_return_t status;
    size_t message_size;
    static bool is_requester = false;
    uint32_t data_link_type;
    libspdm_secured_message_callbacks_t spdm_secured_message_callbacks;
    void *secured_message_context;
    void *spdm_dec_message_buffer;

    data_link_type = get_data_link_type();
    switch (data_link_type) {
    case LINKTYPE_MCTP:
        sequence_num_size = sizeof(uint16_t);
        spdm_secured_message_callbacks.version =
            SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
        spdm_secured_message_callbacks.get_sequence_number =
            libspdm_mctp_get_sequence_number;
        spdm_secured_message_callbacks.get_max_random_number_count =
            libspdm_mctp_get_max_random_number_count;
        break;
    case LINKTYPE_PCI_DOE:
        sequence_num_size = 0;
        spdm_secured_message_callbacks.version =
            SPDM_SECURED_MESSAGE_CALLBACKS_VERSION;
        spdm_secured_message_callbacks.get_sequence_number =
            libspdm_pci_doe_get_sequence_number;
        spdm_secured_message_callbacks.get_max_random_number_count =
            libspdm_pci_doe_get_max_random_number_count;
        break;
    default:
        LIBSPDM_ASSERT(false);
        printf("<UnknownTransportLayer> ");
        printf("\n");
        return;
    }

    if (buffer_size <
        sizeof(spdm_secured_message_a_data_header1_t) + sequence_num_size +
        sizeof(spdm_secured_message_a_data_header2_t)) {
        printf("\n");
        return;
    }

    is_requester = (bool)(!is_requester);

    record_header1 = buffer;
    sequence_num = 0;
    if (data_link_type == LINKTYPE_MCTP) {
        sequence_num = *(uint16_t *)(record_header1 + 1);
    }

    m_current_session_info = libspdm_get_session_info_via_session_id(
        m_spdm_context, record_header1->session_id);
    m_current_session_id = record_header1->session_id;
    status = LIBSPDM_STATUS_UNSUPPORTED_CAP;
    message_size = get_max_packet_length();
    spdm_dec_message_buffer = m_spdm_dec_message_buffer;
    if (m_current_session_info != NULL) {
        secured_message_context =
            libspdm_get_secured_message_context_via_session_id(
                m_spdm_context, record_header1->session_id);
        if (secured_message_context != NULL) {
            status = libspdm_decode_secured_message(
                secured_message_context,
                record_header1->session_id, is_requester,
                buffer_size, buffer, &message_size,
                &spdm_dec_message_buffer,
                &spdm_secured_message_callbacks);
            if (LIBSPDM_STATUS_IS_ERROR(status)) {

                /* Try other direction, because a responder might initiate a message in Session.*/

                status = libspdm_decode_secured_message(
                    secured_message_context,
                    record_header1->session_id,
                    !is_requester, buffer_size, buffer,
                    &message_size,
                    &spdm_dec_message_buffer,
                    &spdm_secured_message_callbacks);
                if (!LIBSPDM_STATUS_IS_ERROR(status)) {
                    is_requester = !is_requester;
                }
            }
        }
    }

    if (!LIBSPDM_STATUS_IS_ERROR(status)) {
        if (is_requester) {
            printf("REQ->RSP ");
        } else {
            printf("RSP->REQ ");
        }
        printf("SecuredSPDM(0x%08x", record_header1->session_id);
        if (data_link_type == LINKTYPE_MCTP) {
            printf(", Seq=0x%04x", sequence_num);
        }
        printf(") ");

        m_decrypted = true;
        dump_dispatch_message(m_secured_spdm_dispatch,
                              LIBSPDM_ARRAY_SIZE(m_secured_spdm_dispatch),
                              get_data_link_type(),
                              spdm_dec_message_buffer, message_size);
        m_decrypted = false;
    } else {
        printf("(?)->(?) ");
        printf("SecuredSPDM(0x%08x", record_header1->session_id);
        if (data_link_type == LINKTYPE_MCTP) {
            printf(", Seq=0x%04x", sequence_num);
        }
        printf(") ");
        printf("<Unknown> ");
        printf("\n");
    }

    if (m_param_dump_hex) {
        printf("  SecuredSPDM message:\n");
        dump_hex(buffer, buffer_size);
    }
}
