/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

void dump_pci_ide_km_query(const void *buffer, size_t buffer_size)
{
    const pci_ide_km_query_t *query;

    printf("QUERY ");

    if (buffer_size < sizeof(pci_ide_km_query_t)) {
        printf("\n");
        return;
    }

    query = buffer;

    if (!m_param_quite_mode) {
        printf("(port=0x%02x) ", query->port_index);
    }

    printf("\n");
}

void dump_pci_ide_km_query_resp(const void *buffer, size_t buffer_size)
{
    const pci_ide_km_query_resp_t *query_resp;

    printf("QUERY_RESP ");

    if (buffer_size < sizeof(pci_ide_km_query_resp_t)) {
        printf("\n");
        return;
    }

    query_resp = buffer;

    if (!m_param_quite_mode) {
        printf("(port=0x%02x, DevFunc=0x%02x, Bus=0x%02x, Seg=0x%02x, MaxPort=0x%02x) ",
               query_resp->port_index, query_resp->dev_func_num,
               query_resp->bus_num, query_resp->segment,
               query_resp->max_port_index);
    }

    printf("\n");
}

void dump_pci_ide_km_key_program(const void *buffer, size_t buffer_size)
{
    const pci_ide_km_key_prog_t *key_prog;

    printf("KEY_PROG ");

    if (buffer_size < sizeof(pci_ide_km_key_prog_t)) {
        printf("\n");
        return;
    }

    key_prog = buffer;

    if (!m_param_quite_mode) {
        printf("(StreamId=0x%02x, KeySubStream=0x%02x (KeySet=%x, RxTx=%x, SubStream=%x), PortIndex=0x%02x) ",
               key_prog->stream_id, key_prog->key_sub_stream,
               key_prog->key_sub_stream & PCI_IDE_KM_KEY_SET_MASK,
               (key_prog->key_sub_stream & PCI_IDE_KM_KEY_DIRECTION_MASK) >> 1,
               (key_prog->key_sub_stream & PCI_IDE_KM_KEY_SUB_STREAM_MASK) >> 4,
               key_prog->port_index);
    }

    printf("\n");
}

void dump_pci_ide_km_key_program_ack(const void *buffer, size_t buffer_size)
{
    const pci_ide_km_kp_ack_t *kp_ack;

    printf("KP_ACK ");

    if (buffer_size < sizeof(pci_ide_km_kp_ack_t)) {
        printf("\n");
        return;
    }

    kp_ack = buffer;

    if (!m_param_quite_mode) {
        printf("(StreamId=0x%02x, Status=0x%02x, KeySubStream=0x%02x (KeySet=%x, RxTx=%x, SubStream=%x), PortIndex=0x%02x) ",
               kp_ack->stream_id, kp_ack->status, kp_ack->key_sub_stream,
               kp_ack->key_sub_stream & PCI_IDE_KM_KEY_SET_MASK,
               (kp_ack->key_sub_stream & PCI_IDE_KM_KEY_DIRECTION_MASK) >> 1,
               (kp_ack->key_sub_stream & PCI_IDE_KM_KEY_SUB_STREAM_MASK) >> 4,
               kp_ack->port_index);
    }

    printf("\n");
}

void dump_pci_ide_km_key_set_go(const void *buffer, size_t buffer_size)
{
    const pci_ide_km_k_set_go_t *k_set_go;

    printf("K_SET_GO ");

    if (buffer_size < sizeof(pci_ide_km_k_set_go_t)) {
        printf("\n");
        return;
    }

    k_set_go = buffer;

    if (!m_param_quite_mode) {
        printf("(StreamId=0x%02x, KeySubStream=0x%02x (KeySet=%x, RxTx=%x, SubStream=%x), PortIndex=0x%02x) ",
               k_set_go->stream_id, k_set_go->key_sub_stream,
               k_set_go->key_sub_stream & PCI_IDE_KM_KEY_SET_MASK,
               (k_set_go->key_sub_stream & PCI_IDE_KM_KEY_DIRECTION_MASK) >> 1,
               (k_set_go->key_sub_stream & PCI_IDE_KM_KEY_SUB_STREAM_MASK) >> 4,
               k_set_go->port_index);
    }

    printf("\n");
}

void dump_pci_ide_km_key_set_stop(const void *buffer, size_t buffer_size)
{
    const pci_ide_km_k_set_stop_t *k_set_stop;

    printf("K_SET_STOP ");

    if (buffer_size < sizeof(pci_ide_km_k_set_stop_t)) {
        printf("\n");
        return;
    }

    k_set_stop = buffer;

    if (!m_param_quite_mode) {
        printf("(StreamId=0x%02x, KeySubStream=0x%02x (KeySet=%x, RxTx=%x, SubStream=%x), PortIndex=0x%02x) ",
               k_set_stop->stream_id, k_set_stop->key_sub_stream,
               k_set_stop->key_sub_stream & PCI_IDE_KM_KEY_SET_MASK,
               (k_set_stop->key_sub_stream & PCI_IDE_KM_KEY_DIRECTION_MASK) >> 1,
               (k_set_stop->key_sub_stream & PCI_IDE_KM_KEY_SUB_STREAM_MASK) >> 4,
               k_set_stop->port_index);
    }

    printf("\n");
}

void dump_pci_ide_km_key_set_gostop_ack(const void *buffer, size_t buffer_size)
{
    const pci_ide_km_k_gostop_ack_t *k_gostop_ack;

    printf("K_SET_GOSTOP_ACK ");

    if (buffer_size < sizeof(pci_ide_km_k_gostop_ack_t)) {
        printf("\n");
        return;
    }

    k_gostop_ack = buffer;

    if (!m_param_quite_mode) {
        printf("(StreamId=0x%02x, KeySubStream=0x%02x (KeySet=%x, RxTx=%x, SubStream=%x), PortIndex=0x%02x) ",
               k_gostop_ack->stream_id, k_gostop_ack->key_sub_stream,
               k_gostop_ack->key_sub_stream & PCI_IDE_KM_KEY_SET_MASK,
               (k_gostop_ack->key_sub_stream & PCI_IDE_KM_KEY_DIRECTION_MASK) >> 1,
               (k_gostop_ack->key_sub_stream & PCI_IDE_KM_KEY_SUB_STREAM_MASK) >> 4,
               k_gostop_ack->port_index);
    }

    printf("\n");
}

dispatch_table_entry_t m_pci_ide_km_dispatch[] = {
    { PCI_IDE_KM_OBJECT_ID_QUERY, "QUERY", dump_pci_ide_km_query },
    { PCI_IDE_KM_OBJECT_ID_QUERY_RESP, "QUERY_RESP",
      dump_pci_ide_km_query_resp },
    { PCI_IDE_KM_OBJECT_ID_KEY_PROG, "KEY_PROG",
      dump_pci_ide_km_key_program },
    { PCI_IDE_KM_OBJECT_ID_KP_ACK, "KP_ACK",
      dump_pci_ide_km_key_program_ack },
    { PCI_IDE_KM_OBJECT_ID_K_SET_GO, "K_SET_GO",
      dump_pci_ide_km_key_set_go },
    { PCI_IDE_KM_OBJECT_ID_K_SET_STOP, "K_SET_STOP",
      dump_pci_ide_km_key_set_stop },
    { PCI_IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK, "K_SET_GOSTOP_ACK",
      dump_pci_ide_km_key_set_gostop_ack },
};

void dump_pci_ide_km_message(const void *buffer, size_t buffer_size)
{
    const pci_ide_km_header_t *pci_ide_km_header;

    if (buffer_size < sizeof(pci_ide_km_header_t)) {
        printf("\n");
        return;
    }
    pci_ide_km_header = buffer;

    printf("IDE_KM(0x%02x) ", pci_ide_km_header->object_id);

    dump_dispatch_message(m_pci_ide_km_dispatch,
                          LIBSPDM_ARRAY_SIZE(m_pci_ide_km_dispatch),
                          pci_ide_km_header->object_id, (uint8_t *)buffer,
                          buffer_size);
}
