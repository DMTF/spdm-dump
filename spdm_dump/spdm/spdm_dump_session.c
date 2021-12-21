/**
    Copyright Notice:
    Copyright 2021 DMTF. All rights reserved.
    License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
**/

#include "spdm_dump.h"

extern uint32_t m_spdm_base_hash_algo;
extern void *m_local_used_cert_chain_buffer;
extern uintn m_local_used_cert_chain_buffer_size;
extern void *m_peer_cert_chain_buffer;
extern uintn m_peer_cert_chain_buffer_size;

void *m_requester_cert_chain_buffer;
uintn m_requester_cert_chain_buffer_size;
void *m_responder_cert_chain_buffer;
uintn m_responder_cert_chain_buffer_size;
void *m_dhe_secret_buffer;
uintn m_dhe_secret_buffer_size;
void *m_psk_buffer;
uintn m_psk_buffer_size;

return_status spdm_dump_session_data_provision(IN void *spdm_context,
                           IN uint32_t session_id,
                           IN boolean need_mut_auth,
                           IN boolean is_requester)
{
    uintn hash_size;
    void *session_info;
    void *secured_message_context;
    libspdm_data_parameter_t parameter;
    boolean use_psk;
    uint8_t mut_auth_requested;
    uintn data_size;

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        ASSERT(FALSE);
        return RETURN_UNSUPPORTED;
    }
    secured_message_context =
        libspdm_get_secured_message_context_via_session_id(spdm_context,
                                session_id);
    if (secured_message_context == NULL) {
        ASSERT(FALSE);
        return RETURN_UNSUPPORTED;
    }

    zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_SESSION;
    *(uint32_t *)parameter.additional_data = session_id;
    data_size = sizeof(use_psk);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SESSION_USE_PSK, &parameter,
              &use_psk, &data_size);
    data_size = sizeof(mut_auth_requested);
    libspdm_get_data(spdm_context, LIBSPDM_DATA_SESSION_MUT_AUTH_REQUESTED,
              &parameter, &mut_auth_requested, &data_size);

    hash_size = libspdm_get_hash_size(m_spdm_base_hash_algo);

    if (!use_psk) {
        if (m_dhe_secret_buffer == NULL ||
            m_dhe_secret_buffer_size == 0) {
            return RETURN_UNSUPPORTED;
        }
        libspdm_secured_message_import_dhe_secret(
            secured_message_context, m_dhe_secret_buffer,
            m_dhe_secret_buffer_size);

        if (is_requester) {
            if (need_mut_auth && mut_auth_requested) {
                if (m_requester_cert_chain_buffer == NULL ||
                    m_requester_cert_chain_buffer_size == 0) {
                    return RETURN_UNSUPPORTED;
                }
                memcpy((uint8_t *)m_local_used_cert_chain_buffer,
                       m_requester_cert_chain_buffer,
                       m_requester_cert_chain_buffer_size);
                m_local_used_cert_chain_buffer_size =
                    m_requester_cert_chain_buffer_size;
                zero_mem(&parameter, sizeof(parameter));
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
                return RETURN_UNSUPPORTED;
            }
            memcpy((uint8_t *)m_peer_cert_chain_buffer,
                   m_responder_cert_chain_buffer,
                   m_responder_cert_chain_buffer_size);
            m_peer_cert_chain_buffer_size =
                m_responder_cert_chain_buffer_size;
            zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
            libspdm_set_data(spdm_context,
                      LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
                      &parameter, m_peer_cert_chain_buffer,
                      m_peer_cert_chain_buffer_size);
        } else {
            if (m_responder_cert_chain_buffer == NULL ||
                m_responder_cert_chain_buffer_size == 0) {
                return RETURN_UNSUPPORTED;
            }
            memcpy((uint8_t *)m_local_used_cert_chain_buffer,
                   m_responder_cert_chain_buffer,
                   m_responder_cert_chain_buffer_size);
            m_local_used_cert_chain_buffer_size =
                m_responder_cert_chain_buffer_size;
            zero_mem(&parameter, sizeof(parameter));
            parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
            libspdm_set_data(spdm_context,
                      LIBSPDM_DATA_LOCAL_USED_CERT_CHAIN_BUFFER,
                      &parameter,
                      m_local_used_cert_chain_buffer,
                      m_local_used_cert_chain_buffer_size);
            if (need_mut_auth && mut_auth_requested) {
                if (m_requester_cert_chain_buffer == NULL ||
                    m_requester_cert_chain_buffer_size == 0) {
                    return RETURN_UNSUPPORTED;
                }
                memcpy((uint8_t *)m_peer_cert_chain_buffer,
                       m_requester_cert_chain_buffer,
                       m_requester_cert_chain_buffer_size);
                m_peer_cert_chain_buffer_size =
                    m_requester_cert_chain_buffer_size;
                zero_mem(&parameter, sizeof(parameter));
                parameter.location =
                    LIBSPDM_DATA_LOCATION_CONNECTION;
                libspdm_set_data(
                    spdm_context,
                    LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
                    &parameter, m_peer_cert_chain_buffer,
                    m_peer_cert_chain_buffer_size);
            }
        }
    } else {
        if (m_psk_buffer == NULL || m_psk_buffer_size == 0) {
            return RETURN_UNSUPPORTED;
        }
        if (m_psk_buffer_size > LIBSPDM_MAX_DHE_KEY_SIZE) {
            printf("BUGBUG: PSK size is too large. It will be supported later.\n");
            return RETURN_UNSUPPORTED;
        }
        libspdm_secured_message_import_dhe_secret(secured_message_context,
                               m_psk_buffer,
                               m_psk_buffer_size);
    }

    return RETURN_SUCCESS;
}

return_status spdm_dump_session_data_check(IN void *spdm_context,
                       IN uint32_t session_id,
                       IN boolean is_requester)
{
    void *session_info;
    libspdm_data_parameter_t parameter;
    boolean use_psk;
    uint8_t mut_auth_requested;
    uintn data_size;

    session_info =
        libspdm_get_session_info_via_session_id(spdm_context, session_id);
    if (session_info == NULL) {
        ASSERT(FALSE);
        return RETURN_UNSUPPORTED;
    }

    zero_mem(&parameter, sizeof(parameter));
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
            return RETURN_UNSUPPORTED;
        }
        if (is_requester) {
            if (mut_auth_requested) {
                if (m_requester_cert_chain_buffer == NULL ||
                    m_requester_cert_chain_buffer_size == 0) {
                    return RETURN_UNSUPPORTED;
                }
            }
            if (m_responder_cert_chain_buffer == NULL ||
                m_responder_cert_chain_buffer_size == 0) {
                return RETURN_UNSUPPORTED;
            }
        } else {
            if (m_responder_cert_chain_buffer == NULL ||
                m_responder_cert_chain_buffer_size == 0) {
                return RETURN_UNSUPPORTED;
            }
            if (mut_auth_requested) {
                if (m_requester_cert_chain_buffer == NULL ||
                    m_requester_cert_chain_buffer_size == 0) {
                    return RETURN_UNSUPPORTED;
                }
            }
        }
    } else {
        if (m_psk_buffer == NULL || m_psk_buffer_size == 0) {
            return RETURN_UNSUPPORTED;
        }
    }

    return RETURN_SUCCESS;
}
