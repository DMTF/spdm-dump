/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

extern uint32_t m_spdm_base_hash_algo;
extern void *m_local_used_cert_chain_buffer;
extern size_t m_local_used_cert_chain_buffer_size;
extern void *m_peer_cert_chain_buffer;
extern size_t m_peer_cert_chain_buffer_size;

void *m_dhe_secret_buffer;
size_t m_dhe_secret_buffer_size;
void *m_psk_buffer;
size_t m_psk_buffer_size;
uint8_t m_use_slot_id = 0;

libspdm_return_t spdm_dump_session_data_provision(void *spdm_context,
                                               uint32_t session_id,
                                               bool need_mut_auth,
                                               bool is_requester)
{
    void *session_info;
    void *secured_message_context;
    libspdm_data_parameter_t parameter;
    bool use_psk;
    uint8_t mut_auth_requested;
    size_t data_size;

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }
    secured_message_context =
        libspdm_get_secured_message_context_via_session_id(spdm_context,
                                                           session_id);
    if (secured_message_context == NULL) {
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    *(uint32_t *)parameter.additional_data = session_id;
    data_size = sizeof(use_psk);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SESSION_USE_PSK, &parameter,
                     &use_psk, &data_size);
    data_size = sizeof(mut_auth_requested);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SESSION_MUT_AUTH_REQUESTED,
                     &parameter, &mut_auth_requested, &data_size);

    if (!use_psk) {
        if (m_dhe_secret_buffer == NULL ||
            m_dhe_secret_buffer_size == 0) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        libspdm_secured_message_import_dhe_secret(
            secured_message_context, m_dhe_secret_buffer,
            m_dhe_secret_buffer_size);

        if (is_requester) {
            if (need_mut_auth && mut_auth_requested) {
                if (m_requester_cert_chain_buffer == NULL ||
                    m_requester_cert_chain_buffer_size == 0) {
                    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
                }
                memcpy((uint8_t *)m_local_used_cert_chain_buffer,
                       m_requester_cert_chain_buffer,
                       m_requester_cert_chain_buffer_size);
                m_local_used_cert_chain_buffer_size =
                    m_requester_cert_chain_buffer_size;
                libspdm_zero_mem(&parameter, sizeof(parameter));
                parameter.location =
                    LIBSPDM_DATA_LOCATION_CONNECTION;
                libspdm_set_data(
                    spdm_context,
                    LIBSPDM_DATA_LOCAL_USED_CERT_CHAIN_BUFFER,
                    &parameter,
                    m_local_used_cert_chain_buffer,
                    m_local_used_cert_chain_buffer_size);
            }
            if (m_responder_cert_chain_buffer == NULL ||
                m_responder_cert_chain_buffer_size == 0) {
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
            memcpy((uint8_t *)m_peer_cert_chain_buffer,
                   m_responder_cert_chain_buffer,
                   m_responder_cert_chain_buffer_size);
            m_peer_cert_chain_buffer_size =
                m_responder_cert_chain_buffer_size;
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.additional_data[0] = m_use_slot_id;
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
            libspdm_set_data(spdm_context,
                             LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
                             &parameter, m_peer_cert_chain_buffer,
                             m_peer_cert_chain_buffer_size);
        } else {
            if (m_responder_cert_chain_buffer == NULL ||
                m_responder_cert_chain_buffer_size == 0) {
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
            memcpy((uint8_t *)m_local_used_cert_chain_buffer,
                   m_responder_cert_chain_buffer,
                   m_responder_cert_chain_buffer_size);
            m_local_used_cert_chain_buffer_size =
                m_responder_cert_chain_buffer_size;
            libspdm_zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
            libspdm_set_data(spdm_context,
                             LIBSPDM_DATA_LOCAL_USED_CERT_CHAIN_BUFFER,
                             &parameter,
                             m_local_used_cert_chain_buffer,
                             m_local_used_cert_chain_buffer_size);
            if (need_mut_auth && mut_auth_requested) {
                if (m_requester_cert_chain_buffer == NULL ||
                    m_requester_cert_chain_buffer_size == 0) {
                    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
                }
                memcpy((uint8_t *)m_peer_cert_chain_buffer,
                       m_requester_cert_chain_buffer,
                       m_requester_cert_chain_buffer_size);
                m_peer_cert_chain_buffer_size =
                    m_requester_cert_chain_buffer_size;
                libspdm_zero_mem(&parameter, sizeof(parameter));
                parameter.location =
                    LIBSPDM_DATA_LOCATION_CONNECTION;
                parameter.additional_data[0] = m_use_slot_id;
                libspdm_set_data(
                    spdm_context,
                    LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
                    &parameter, m_peer_cert_chain_buffer,
                    m_peer_cert_chain_buffer_size);
            }
        }
    } else {
        if (m_psk_buffer == NULL || m_psk_buffer_size == 0) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        if (m_psk_buffer_size > LIBSPDM_MAX_DHE_KEY_SIZE) {
            printf("BUGBUG: PSK size is too large. It will be supported later.\n");
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        libspdm_secured_message_import_dhe_secret(secured_message_context,
                                                  m_psk_buffer,
                                                  m_psk_buffer_size);
    }

    return LIBSPDM_STATUS_SUCCESS;
}

libspdm_return_t spdm_dump_session_data_check(void *spdm_context,
                                           uint32_t session_id,
                                           bool is_requester)
{
    void *session_info;
    libspdm_data_parameter_t parameter;
    bool use_psk;
    uint8_t mut_auth_requested;
    size_t data_size;

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        LIBSPDM_ASSERT(false);
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    *(uint32_t *)parameter.additional_data = session_id;
    data_size = sizeof(use_psk);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SESSION_USE_PSK, &parameter,
                     &use_psk, &data_size);
    data_size = sizeof(mut_auth_requested);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SESSION_MUT_AUTH_REQUESTED,
                     &parameter, &mut_auth_requested, &data_size);

    if (!use_psk) {
        if (m_dhe_secret_buffer == NULL ||
            m_dhe_secret_buffer_size == 0) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        if (is_requester) {
            if (mut_auth_requested) {
                if (m_requester_cert_chain_buffer == NULL ||
                    m_requester_cert_chain_buffer_size == 0) {
                    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
                }
            }
            if (m_responder_cert_chain_buffer == NULL ||
                m_responder_cert_chain_buffer_size == 0) {
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
        } else {
            if (m_responder_cert_chain_buffer == NULL ||
                m_responder_cert_chain_buffer_size == 0) {
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
            if (mut_auth_requested) {
                if (m_requester_cert_chain_buffer == NULL ||
                    m_requester_cert_chain_buffer_size == 0) {
                    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
                }
            }
        }
    } else {
        if (m_psk_buffer == NULL || m_psk_buffer_size == 0) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}
