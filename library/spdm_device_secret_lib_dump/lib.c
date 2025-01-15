/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/libspdm/blob/main/LICENSE.md
 **/

/** @file
 * SPDM common library.
 * It follows the SPDM Specification.
 **/

#include "hal/library/memlib.h"
#include "hal/library/responder/asymsignlib.h"
#include "hal/library/responder/csrlib.h"
#include "hal/library/responder/measlib.h"
#include "hal/library/responder/psklib.h"
#include "hal/library/responder/setcertlib.h"
#include "hal/library/requester/reqasymsignlib.h"
#include "hal/library/requester/psklib.h"
#include "library/spdm_crypt_lib.h"

#if LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP
libspdm_return_t libspdm_measurement_collection(
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t mesurements_index,
    uint8_t request_attribute,
    uint8_t *content_changed,
    uint8_t *device_measurement_count,
    void *device_measurement,
    size_t *device_measurement_size)
{
    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}

bool libspdm_measurement_opaque_data(
    spdm_version_number_t spdm_version,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_index,
    uint8_t request_attribute,
    void *opaque_data,
    size_t *opaque_data_size)
{
    return false;
}

bool libspdm_challenge_opaque_data(
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *measurement_summary_hash,
    size_t measurement_summary_hash_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    return false;
}

bool libspdm_encap_challenge_opaque_data(
    spdm_version_number_t spdm_version,
    uint8_t slot_id,
    uint8_t *measurement_summary_hash,
    size_t measurement_summary_hash_size,
    void *opaque_data,
    size_t *opaque_data_size)
{
    return false;
}

bool libspdm_generate_measurement_summary_hash(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    uint8_t measurement_specification,
    uint32_t measurement_hash_algo,
    uint8_t measurement_summary_hash_type,
    uint8_t  *measurement_summary_hash,
    uint32_t measurement_summary_hash_size)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MEAS_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP
bool libspdm_requester_data_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    return false;
}

bool libspdm_requester_data_pqc_sign(
    void *spdm_context,
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t req_pqc_asym_alg,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_MUT_AUTH_CAP */

bool libspdm_responder_data_sign(
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    return false;
}

bool libspdm_responder_data_pqc_sign(
    void *spdm_context,
    spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_pqc_algo,
    uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size,
    uint8_t *signature, size_t *sig_size)
{
    return false;
}

#if LIBSPDM_ENABLE_CAPABILITY_PSK_CAP

void *m_spdm_dump_psk;
size_t m_spdm_dump_psk_size;

uint8_t m_spdm_dump_my_zero_filled_buffer[LIBSPDM_MAX_HASH_SIZE];
uint8_t m_spdm_dump_my_salt0[LIBSPDM_MAX_HASH_SIZE];
uint8_t m_spdm_dump_bin_str0[0x11] = {
    0x00, 0x00, /* length - to be filled*/
    /* SPDM_VERSION_1_1_BIN_CONCAT_LABEL */
    0x73, 0x70, 0x64, 0x6d, 0x31, 0x2e, 0x31, 0x20,
    /* SPDM_BIN_STR_0_LABEL */
    0x64, 0x65, 0x72, 0x69, 0x76, 0x65, 0x64,
};

bool libspdm_psk_handshake_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size,
    uint8_t *out, size_t out_size)
{
    void *psk;
    size_t psk_size;
    size_t hash_size;
    bool result;
    uint8_t handshake_secret[LIBSPDM_MAX_HASH_SIZE];

    if ((spdm_version >> SPDM_VERSION_NUMBER_SHIFT_BIT) >= SPDM_MESSAGE_VERSION_13) {
        libspdm_set_mem(m_spdm_dump_my_salt0, sizeof(m_spdm_dump_my_salt0), 0xff);
    }

    if (m_spdm_dump_psk == NULL) {
        return false;
    }
    psk = m_spdm_dump_psk;
    psk_size = m_spdm_dump_psk_size;

    hash_size = libspdm_get_hash_size(base_hash_algo);

    result = libspdm_hkdf_extract(base_hash_algo, psk, psk_size, m_spdm_dump_my_salt0,
                                  hash_size, handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_expand(base_hash_algo, handshake_secret, hash_size,
                                 info, info_size, out, out_size);
    libspdm_zero_mem(handshake_secret, hash_size);

    return result;
}

bool libspdm_psk_master_secret_hkdf_expand(
    spdm_version_number_t spdm_version,
    uint32_t base_hash_algo,
    const uint8_t *psk_hint,
    size_t psk_hint_size,
    const uint8_t *info,
    size_t info_size, uint8_t *out,
    size_t out_size)
{
    void *psk;
    size_t psk_size;
    size_t hash_size;
    bool result;
    uint8_t handshake_secret[LIBSPDM_MAX_HASH_SIZE];
    uint8_t salt1[LIBSPDM_MAX_HASH_SIZE];
    uint8_t master_secret[LIBSPDM_MAX_HASH_SIZE];

    if (m_spdm_dump_psk == NULL) {
        return false;
    }
    psk = m_spdm_dump_psk;
    psk_size = m_spdm_dump_psk_size;

    hash_size = libspdm_get_hash_size(base_hash_algo);

    result = libspdm_hkdf_extract(base_hash_algo, psk, psk_size, m_spdm_dump_my_salt0,
                                  hash_size, handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    *(uint16_t *)m_spdm_dump_bin_str0 = (uint16_t)hash_size;
    /* patch the version*/
    m_spdm_dump_bin_str0[6] = (char)('0' + ((spdm_version >> 12) & 0xF));
    m_spdm_dump_bin_str0[8] = (char)('0' + ((spdm_version >> 8) & 0xF));
    result = libspdm_hkdf_expand(base_hash_algo, handshake_secret, hash_size,
                                 m_spdm_dump_bin_str0, sizeof(m_spdm_dump_bin_str0), salt1,
                                 hash_size);
    libspdm_zero_mem(handshake_secret, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_extract(base_hash_algo, m_spdm_dump_my_zero_filled_buffer,
                                  hash_size, salt1, hash_size, master_secret, hash_size);
    libspdm_zero_mem(salt1, hash_size);
    if (!result) {
        return result;
    }

    result = libspdm_hkdf_expand(base_hash_algo, master_secret, hash_size,
                                 info, info_size, out, out_size);
    libspdm_zero_mem(master_secret, hash_size);

    return result;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_PSK_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP
bool libspdm_is_in_trusted_environment()
{
    return false;
}

bool libspdm_write_certificate_to_nvm(uint8_t slot_id, const void * cert_chain,
                                      size_t cert_chain_size,
                                      uint32_t base_hash_algo, uint32_t base_asym_algo)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_SET_CERT_CAP */

#if LIBSPDM_ENABLE_CAPABILITY_CSR_CAP
bool libspdm_gen_csr(uint32_t base_hash_algo, uint32_t base_asym_algo, bool *need_reset,
                     const void *request, size_t request_size,
                     uint8_t *requester_info, size_t requester_info_length,
                     uint8_t *opaque_data, uint16_t opaque_data_length,
                     size_t *csr_len, uint8_t *csr_pointer,
                     bool is_device_cert_model)
{
    return false;
}
#endif /* LIBSPDM_ENABLE_CAPABILITY_CSR_CAP */
