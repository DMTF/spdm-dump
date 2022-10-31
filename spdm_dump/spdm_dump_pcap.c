/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

#define PCAP_PACKET_MAX_SIZE 0x00010000

pcap_global_header_t m_pcap_global_header;
FILE *m_pcap_file;
void *m_pcap_packet_data_buffer;

dispatch_table_entry_t m_pcap_dispatch[] = {
    { LINKTYPE_MCTP, "MCTP", dump_mctp_packet },
    { LINKTYPE_PCI_DOE, "PCI_DOE", dump_pci_doe_packet },
};

char *data_link_type_to_string(uint32_t data_link_type)
{
    switch (data_link_type) {
    case LINKTYPE_MCTP:
        return "MCTP";
    case LINKTYPE_PCI_DOE:
        return "PCI_DOE";
    default:
        return "<Unknown>";
    }
}

uint32_t get_max_packet_length(void)
{
    return m_pcap_global_header.snap_len;
}

uint32_t get_data_link_type(void)
{
    return m_pcap_global_header.network;
}

void dump_pcap_global_header(const pcap_global_header_t *pcap_global_header)
{
    printf("PcapFile: Magic - '%x', version%d.%d, DataLink - %d (%s), MaxPacketSize - %d\n",
           pcap_global_header->magic_number,
           pcap_global_header->version_major,
           pcap_global_header->version_minor, pcap_global_header->network,
           data_link_type_to_string(pcap_global_header->network),
           pcap_global_header->snap_len);
}

bool open_pcap_packet_file(const char *pcap_file_name)
{
    if (pcap_file_name == NULL) {
        return false;
    }

    if ((m_pcap_file = fopen(pcap_file_name, "rb")) == NULL) {
        printf("!!!Unable to open pcap file %s!!!\n", pcap_file_name);
        return false;
    }

    if (fread(&m_pcap_global_header, 1, sizeof(pcap_global_header_t),
              m_pcap_file) != sizeof(pcap_global_header_t)) {
        printf("!!!Unable to read the pcap global header!!!\n");
        return false;
    }

    if ((m_pcap_global_header.magic_number != PCAP_GLOBAL_HEADER_MAGIC) &&
        (m_pcap_global_header.magic_number !=
         PCAP_GLOBAL_HEADER_MAGIC_SWAPPED) &&
        (m_pcap_global_header.magic_number !=
         PCAP_GLOBAL_HEADER_MAGIC_NANO) &&
        (m_pcap_global_header.magic_number !=
         PCAP_GLOBAL_HEADER_MAGIC_NANO_SWAPPED)) {
        printf("!!!pcap file magic invalid '%x'!!!\n",
               m_pcap_global_header.magic_number);
        return false;
    }

    dump_pcap_global_header(&m_pcap_global_header);

    if (m_pcap_global_header.snap_len == 0 || m_pcap_global_header.snap_len > PCAP_PACKET_MAX_SIZE) {
        return false;
    }

    m_pcap_packet_data_buffer =
        (void *)malloc(m_pcap_global_header.snap_len);
    if (m_pcap_packet_data_buffer == NULL) {
        printf("!!!memory out of resources!!!\n");
        return false;
    }

    return true;
}

void close_pcap_packet_file(void)
{
    if (m_pcap_file != NULL) {
        fclose(m_pcap_file);
        m_pcap_file = NULL;
    }
    if (m_pcap_packet_data_buffer != NULL) {
        free(m_pcap_packet_data_buffer);
        m_pcap_packet_data_buffer = NULL;
    }
}

void dump_pcap_packet_header(size_t index,
                             const pcap_packet_header_t *pcap_packet_header)
{
    printf("%d (%d) ", (uint32_t)index, pcap_packet_header->ts_sec);
}

void dump_pcap_packet(const void *buffer, size_t buffer_size)
{
    dump_dispatch_message(m_pcap_dispatch, LIBSPDM_ARRAY_SIZE(m_pcap_dispatch),
                          m_pcap_global_header.network, buffer,
                          buffer_size);
}

void dump_pcap(void)
{
    pcap_packet_header_t pcap_packet_header;
    size_t index;

    index = 1;

    while (true) {
        if (fread(&pcap_packet_header, 1, sizeof(pcap_packet_header_t),
                  m_pcap_file) != sizeof(pcap_packet_header_t)) {
            return;
        }
        dump_pcap_packet_header(index++, &pcap_packet_header);
        if (pcap_packet_header.incl_len == 0 || pcap_packet_header.incl_len > PCAP_PACKET_MAX_SIZE) {
            return;
        }
        if (fread(m_pcap_packet_data_buffer, 1,
                  pcap_packet_header.incl_len,
                  m_pcap_file) != pcap_packet_header.incl_len) {
            return;
        }
        dump_pcap_packet(m_pcap_packet_data_buffer,
                         pcap_packet_header.incl_len);
    }
}
