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

void *m_dhe_secret_buffer[LIBSPDM_MAX_SESSION_COUNT] = {NULL};
size_t m_dhe_secret_buffer_size[LIBSPDM_MAX_SESSION_COUNT] = {0};
void *m_psk_buffer[LIBSPDM_MAX_SESSION_COUNT] = {NULL};
size_t m_psk_buffer_size[LIBSPDM_MAX_SESSION_COUNT] = {0};
uint8_t m_responder_cert_chain_slot_id = 0;
uint8_t m_requester_cert_chain_slot_id = 0;


/*current used key index, index++ when finish command dump complete*/
uint8_t m_dhe_secret_buffer_count = 0;
uint8_t m_psk_secret_buffer_count = 0;

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
    size_t hash_size;
    spdm_cert_chain_t *cert_chain_header;
    const uint8_t *root_cert;
    size_t root_cert_len;
    bool res;
    size_t cert_chain_offset;

    LIBSPDM_ASSERT (m_requester_cert_chain_slot_id <= SPDM_MAX_SLOT_COUNT);
    LIBSPDM_ASSERT (m_responder_cert_chain_slot_id <= SPDM_MAX_SLOT_COUNT);

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
        if (m_dhe_secret_buffer[m_dhe_secret_buffer_count] == NULL ||
            m_dhe_secret_buffer_size[m_dhe_secret_buffer_count] == 0) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        libspdm_secured_message_import_dhe_secret(
            secured_message_context, m_dhe_secret_buffer[m_dhe_secret_buffer_count],
            m_dhe_secret_buffer_size[m_dhe_secret_buffer_count]);

        hash_size = libspdm_get_hash_size(m_spdm_base_hash_algo);

        if (m_cert_chain_format == CERT_CHAIN_FORMAT_SPDM) {
            cert_chain_offset = 0;
        } else {
            cert_chain_offset = sizeof(spdm_cert_chain_t) + hash_size;
        }

        /* rule: cert_chain_data (from user) override cert_chain_buffer (from transport message) */
        if (m_requester_cert_chain_data[m_requester_cert_chain_slot_id] != NULL &&
            m_requester_cert_chain_data_size[m_requester_cert_chain_slot_id] != 0) {
            if (m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] != NULL) {
                free (m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id]);
            }
            m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id] = 0;
            /* data from user stored in m_requester_cert_chain_buffer[SPDM_MAX_SLOT_COUNT]
             * is raw public key provisioned for slot_id - 0xFF */
            if (m_requester_cert_chain_slot_id == SPDM_MAX_SLOT_COUNT) {
                m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] =
                    malloc(m_requester_cert_chain_data_size[m_requester_cert_chain_slot_id]);
                if (m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] != NULL) {
                    memcpy(
                        (uint8_t *)m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id],
                        m_requester_cert_chain_data[m_requester_cert_chain_slot_id],
                        m_requester_cert_chain_data_size[m_requester_cert_chain_slot_id]);
                    m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id] =
                        m_requester_cert_chain_data_size[m_requester_cert_chain_slot_id];
                }
            } else {
                m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] =
                    malloc(m_requester_cert_chain_data_size[m_requester_cert_chain_slot_id] +
                           cert_chain_offset);
                if (m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] != NULL) {
                    memcpy(
                        (uint8_t *)m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] +
                        cert_chain_offset,
                        m_requester_cert_chain_data[m_requester_cert_chain_slot_id],
                        m_requester_cert_chain_data_size[m_requester_cert_chain_slot_id]);
                    m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id] =
                        m_requester_cert_chain_data_size[m_requester_cert_chain_slot_id] +
                        cert_chain_offset;
                    if (cert_chain_offset != 0) {
                        cert_chain_header =
                            m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id];
                        cert_chain_header->length =
                            (uint16_t)(
                                m_requester_cert_chain_data_size[m_requester_cert_chain_slot_id] +
                                cert_chain_offset);
                        cert_chain_header->reserved = 0;
                        res = libspdm_x509_get_cert_from_cert_chain(
                                m_requester_cert_chain_data[m_requester_cert_chain_slot_id],
                                m_requester_cert_chain_data_size[m_requester_cert_chain_slot_id],
                                0, &root_cert, &root_cert_len);
                        if (!res) {
                            free (m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id]);
                            m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] = NULL;
                        } else {
                            libspdm_hash_all (
                                m_spdm_base_hash_algo,
                                root_cert, root_cert_len,
                                (uint8_t *)(cert_chain_header + 1));
                        }
                    }
                }
            }
        }
        if (m_responder_cert_chain_data[m_responder_cert_chain_slot_id] != NULL &&
            m_responder_cert_chain_data_size[m_responder_cert_chain_slot_id] != 0) {
            if (m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] != NULL) {
                free (m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id]);
            }
            m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id] = 0;
            /* data from user stored in m_responder_cert_chain_buffer[SPDM_MAX_SLOT_COUNT]
             * is raw public key provisioned for slot_id - 0xFF */
            if (m_responder_cert_chain_slot_id == SPDM_MAX_SLOT_COUNT) {
                m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] =
                    malloc(m_responder_cert_chain_data_size[m_responder_cert_chain_slot_id]);
                if (m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] != NULL) {
                    memcpy(
                        (uint8_t *)m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id],
                        m_responder_cert_chain_data[m_responder_cert_chain_slot_id],
                        m_responder_cert_chain_data_size[m_responder_cert_chain_slot_id]);
                    m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id] =
                        m_responder_cert_chain_data_size[m_responder_cert_chain_slot_id];
                }
            } else {
                m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] =
                    malloc(m_responder_cert_chain_data_size[m_responder_cert_chain_slot_id] +
                           cert_chain_offset);
                if (m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] != NULL) {
                    memcpy(
                        (uint8_t *)m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] +
                        cert_chain_offset,
                        m_responder_cert_chain_data[m_responder_cert_chain_slot_id],
                        m_responder_cert_chain_data_size[m_responder_cert_chain_slot_id]);
                    m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id] =
                        m_responder_cert_chain_data_size[m_responder_cert_chain_slot_id] +
                        cert_chain_offset;
                    if (cert_chain_offset != 0) {
                        cert_chain_header =
                            m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id];
                        cert_chain_header->length =
                            (uint16_t)(
                                m_responder_cert_chain_data_size[m_responder_cert_chain_slot_id] +
                                cert_chain_offset);
                        cert_chain_header->reserved = 0;
                        res = libspdm_x509_get_cert_from_cert_chain(
                                m_responder_cert_chain_data[m_responder_cert_chain_slot_id],
                                m_responder_cert_chain_data_size[m_responder_cert_chain_slot_id],
                                0, &root_cert, &root_cert_len);
                        if (!res) {
                            free (m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id]);
                            m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] = NULL;
                        } else {
                            libspdm_hash_all (
                                m_spdm_base_hash_algo,
                                root_cert, root_cert_len,
                                (uint8_t *)(cert_chain_header + 1));
                        }
                    }
                }
            }
        }

        if (is_requester) {
            if (need_mut_auth && mut_auth_requested) {
                if (m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] == NULL ||
                    m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id] == 0) {
                    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
                }
                memcpy((uint8_t *)m_local_used_cert_chain_buffer,
                       m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id],
                       m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id]);
                m_local_used_cert_chain_buffer_size =
                    m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id];
                libspdm_zero_mem(&parameter, sizeof(parameter));
                if (m_requester_cert_chain_slot_id == SPDM_MAX_SLOT_COUNT) {
                    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                    libspdm_set_data(spdm_context,
                                     LIBSPDM_DATA_LOCAL_PUBLIC_KEY,
                                     &parameter,
                                     m_local_used_cert_chain_buffer,
                                     m_local_used_cert_chain_buffer_size);
                    ((libspdm_context_t *)spdm_context)->
                    connection_info.local_used_cert_chain_slot_id = 0xFF;
                } else {
                    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
                    libspdm_set_data(spdm_context,
                                     LIBSPDM_DATA_LOCAL_USED_CERT_CHAIN_BUFFER,
                                     &parameter,
                                     m_local_used_cert_chain_buffer,
                                     m_local_used_cert_chain_buffer_size);
                    ((libspdm_context_t *)spdm_context)->
                    connection_info.local_used_cert_chain_slot_id = m_requester_cert_chain_slot_id;
                }
            }
            if (m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] == NULL ||
                m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id] == 0) {
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
            memcpy((uint8_t *)m_peer_cert_chain_buffer,
                   m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id],
                   m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id]);
            m_peer_cert_chain_buffer_size =
                m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id];
            libspdm_zero_mem(&parameter, sizeof(parameter));
            if (m_responder_cert_chain_slot_id == SPDM_MAX_SLOT_COUNT) {
                parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_PEER_PUBLIC_KEY,
                                 &parameter,
                                 m_peer_cert_chain_buffer,
                                 m_peer_cert_chain_buffer_size);
                ((libspdm_context_t *)spdm_context)->
                connection_info.peer_used_cert_chain_slot_id = 0xFF;
            } else {
                parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
                parameter.additional_data[0] = m_responder_cert_chain_slot_id;
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
                                 &parameter,
                                 m_peer_cert_chain_buffer,
                                 m_peer_cert_chain_buffer_size);
            }
        } else {
            if (m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] == NULL ||
                m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id] == 0) {
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
            memcpy((uint8_t *)m_local_used_cert_chain_buffer,
                   m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id],
                   m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id]);
            m_local_used_cert_chain_buffer_size =
                m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id];
            libspdm_zero_mem(&parameter, sizeof(parameter));
            if (m_responder_cert_chain_slot_id == SPDM_MAX_SLOT_COUNT) {
                parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_LOCAL_PUBLIC_KEY,
                                 &parameter,
                                 m_local_used_cert_chain_buffer,
                                 m_local_used_cert_chain_buffer_size);
                ((libspdm_context_t *)spdm_context)->
                connection_info.local_used_cert_chain_slot_id = 0xFF;
            } else {
                parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
                libspdm_set_data(spdm_context,
                                 LIBSPDM_DATA_LOCAL_USED_CERT_CHAIN_BUFFER,
                                 &parameter,
                                 m_local_used_cert_chain_buffer,
                                 m_local_used_cert_chain_buffer_size);
                ((libspdm_context_t *)spdm_context)->
                connection_info.local_used_cert_chain_slot_id = m_responder_cert_chain_slot_id;
            }
            if (need_mut_auth && mut_auth_requested) {
                if (m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] == NULL ||
                    m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id] == 0) {
                    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
                }
                memcpy((uint8_t *)m_peer_cert_chain_buffer,
                       m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id],
                       m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id]);
                m_peer_cert_chain_buffer_size =
                    m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id];
                libspdm_zero_mem(&parameter, sizeof(parameter));
                if (m_requester_cert_chain_slot_id == SPDM_MAX_SLOT_COUNT) {
                    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
                    libspdm_set_data(spdm_context,
                                     LIBSPDM_DATA_PEER_PUBLIC_KEY,
                                     &parameter,
                                     m_peer_cert_chain_buffer,
                                     m_peer_cert_chain_buffer_size);
                    ((libspdm_context_t *)spdm_context)->
                    connection_info.peer_used_cert_chain_slot_id = 0xFF;
                } else {
                    parameter.location = LIBSPDM_DATA_LOCATION_CONNECTION;
                    parameter.additional_data[0] = m_requester_cert_chain_slot_id;
                    libspdm_set_data(spdm_context,
                                     LIBSPDM_DATA_PEER_USED_CERT_CHAIN_BUFFER,
                                     &parameter,
                                     m_peer_cert_chain_buffer,
                                     m_peer_cert_chain_buffer_size);
                }
            }
        }
    } else {
        if (m_psk_buffer[m_psk_secret_buffer_count] == NULL ||
            m_psk_buffer_size[m_psk_secret_buffer_count] == 0) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        if (m_psk_buffer_size[m_psk_secret_buffer_count] > LIBSPDM_MAX_DHE_KEY_SIZE) {
            printf("BUGBUG: PSK size is too large. It will be supported later.\n");
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        libspdm_secured_message_import_dhe_secret(secured_message_context,
                                                  m_psk_buffer[m_psk_secret_buffer_count],
                                                  m_psk_buffer_size[m_psk_secret_buffer_count]);
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
        if (m_dhe_secret_buffer[m_dhe_secret_buffer_count] == NULL ||
            m_dhe_secret_buffer_size[m_dhe_secret_buffer_count] == 0) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        if (is_requester) {
            if (mut_auth_requested) {
                if (m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] == NULL ||
                    m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id] == 0) {
                    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
                }
            }
            if (m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] == NULL ||
                m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id] == 0) {
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
        } else {
            if (m_responder_cert_chain_buffer[m_responder_cert_chain_slot_id] == NULL ||
                m_responder_cert_chain_buffer_size[m_responder_cert_chain_slot_id] == 0) {
                return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
            }
            if (mut_auth_requested) {
                if (m_requester_cert_chain_buffer[m_requester_cert_chain_slot_id] == NULL ||
                    m_requester_cert_chain_buffer_size[m_requester_cert_chain_slot_id] == 0) {
                    return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
                }
            }
        }
    } else {
        if (m_psk_buffer[m_psk_secret_buffer_count] == NULL ||
            m_psk_buffer_size[m_psk_secret_buffer_count] == 0) {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
    }

    return LIBSPDM_STATUS_SUCCESS;
}
