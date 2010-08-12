#define _POSIX_SOURCE 1

#include <gnutls/gnutls.h>
#include <string.h>
#include <stdio.h>
#include "libsstp.h"
#include <stdlib.h>
#include <arpa/inet.h>

int is_control_packet(sstp_header_t* pkt_hdr)
{
  return (pkt_hdr->reserved & 1);
}

void sstp_send(gnutls_session_t* tls, void* data, size_t len)
{
  ssize_t sbytes;
  
  sbytes = -1;
  sbytes = gnutls_record_send (*tls, data, len);
  printf("--> %lu bytes\n", len);
  
  if (sbytes < 0) 
    {
      gnutls_perror(sbytes);
      exit(1);
    }
  
}

void* sstp_recv(gnutls_session_t* tls) 
{
  int rbytes;
  char* buf;
  size_t rbuf_size;

  rbytes = -1;
  rbuf_size = BUFFER_SIZE;
  buf = (char*) xmalloc(rbuf_size);
  
  rbytes = gnutls_record_recv (*tls, buf, rbuf_size-1);
  printf("<-- %d bytes\n", rbytes);
  
  if (rbytes < 0)
    {
      gnutls_perror(rbytes);
      free(buf);
      exit(1);
    }
  
  return buf;
}

void send_sstp_packet(gnutls_session_t* tls, int type, void* data, size_t len)
{
  sstp_header_t pkt_hdr;
  size_t sstp_hdr_len = sizeof(sstp_header_t);
  size_t total_length = sstp_hdr_len + len;
  void *pkt = NULL;

  memset(&pkt_hdr, 0, sstp_hdr_len);
  
  pkt_hdr.version = 0x10;
  pkt_hdr.reserved = type;
  pkt_hdr.length = htons(total_length); 

#ifdef _DEBUG_ON
  printf("header:%lu data:%lu total:%lu\n", sstp_hdr_len , len, total_length);
#endif
  
  pkt = xmalloc(total_length);
  
  memcpy(pkt, &pkt_hdr, sstp_hdr_len);
  memcpy(pkt + sstp_hdr_len, data, len);
  
  sstp_send(tls, pkt, total_length);
  
  free(pkt);
}


void send_sstp_data_packet(gnutls_session_t* tls, void* data, size_t len) 
{
  send_sstp_packet(tls, SSTP_DATA_PACKET, data, len); 
}


void send_sstp_control_packet(gnutls_session_t* tls, uint8_t msg_type,
			      sstp_attribute_header_t* attrs, size_t len)
{
  sstp_control_header_t ctrl_hdr;
  size_t ctrl_hdr_len;
  size_t ctrl_len;
  void* data;

  ctrl_hdr_len = sizeof(sstp_control_header_t);
  ctrl_len = ctrl_hdr_len + len;
  
  memset(&ctrl_hdr, 0, sizeof(sstp_control_header_t));
  
  ctrl_hdr.message_type = htons(msg_type);
  ctrl_hdr.num_attributes = htons(0x1);
  
  data = xmalloc(ctrl_len);
  memcpy(data, &ctrl_hdr, ctrl_hdr_len);
  memcpy(data + ctrl_hdr_len, attrs, len);

  send_sstp_packet(tls, SSTP_CONTROL_PACKET, data, ctrl_len);

  free(data);
}


void init_sstp(gnutls_session_t* tls)
{
  sstp_attribute_header_t attr_hdr;
  uint16_t attr_data;
  size_t sstp_attr_hdr_len, sstp_attr_len;
  void* data;
  
  sstp_attr_hdr_len = sizeof(sstp_attribute_header_t);
  sstp_attr_len = sstp_attr_hdr_len + sizeof(uint16_t);
  
  data = xmalloc(sstp_attr_hdr_len);
  
  attr_data = htons(SSTP_ENCAPSULATED_PROTOCOL_PPP);
  attr_hdr.reserved = 0;
  attr_hdr.attribute_id = SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID;
  attr_hdr.packet_length = htons(sstp_attr_len);
  
  memcpy(data, &attr_hdr, sstp_attr_hdr_len);
  memcpy(data + sstp_attr_hdr_len, &attr_data, sizeof(uint16_t));

  send_sstp_control_packet(tls, SSTP_MSG_CALL_CONNECT_REQUEST, data, sstp_attr_len);

  free(data);
  
  data = sstp_recv(tls);
  free(data);
}

