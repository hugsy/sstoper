#include <gnutls/gnutls.h>
#include <string.h>
#include <stdio.h>
#include "libsstp.h"
#include <stdlib.h>


int is_control_packet(sstp_header_t* pkt_hdr)
{
  return (pkt_hdr->reserved & 1);
}

void sstp_send(gnutls_session_t* tls, void* data, size_t len)
{
  ssize_t sbytes = 0;
  
  printf("--> Sending %lu bytes\n", len);
  sbytes = gnutls_record_send (*tls, data, len);

  if (sbytes < 0) 
    {
      gnutls_perror(sbytes);
      exit(1);
    }
    
  return;
}

void* sstp_recv(gnutls_session_t* tls) 
{
  int rbytes = 0;
  char* buf;
  size_t rbuf_size = 1024;
  
  buf = (char*) xmalloc(rbuf_size);
  rbytes = gnutls_record_recv (*tls, buf, rbuf_size-1);

  printf("<-- Received %d bytes\n", rbytes);
  if (rbytes < 0)
    {
      gnutls_perror(rbytes);
      exit(1);
    }
  
  return buf;
}

void send_sstp_packet(gnutls_session_t* tls, int type, void* data, size_t len)
{
  sstp_header_t pkt_hdr;
  size_t total_length = 0;
  void *pkt = NULL;
  
  memset(&pkt_hdr, 0, sizeof(sstp_header_t));
  
  pkt_hdr.version = 0x10;
  pkt_hdr.reserved = type;
  pkt_hdr.length = total_length;

  total_length = sizeof(sstp_header_t) + len;
#ifdef _DEBUG_ON
  printf("header:%lu data:%lu\n", sizeof(sstp_header_t) , len );
#endif
  pkt = xmalloc(total_length);
  memcpy(pkt, &pkt_hdr, sizeof(sstp_header_t));
  memcpy(pkt+sizeof(sstp_header_t), data, len);
  
  sstp_send(tls, pkt, total_length);
  
  free(pkt);
}


void send_sstp_data_packet(gnutls_session_t* tls, void* data, size_t len) 
{
  send_sstp_packet(tls, SSTP_DATA_PACKET, (void*)data, len); 
}


void send_sstp_control_packet(gnutls_session_t* tls, uint8_t msg_type,
			      sstp_attribute_header_t* attrs, size_t len)
{
  sstp_control_header_t ctrl_hdr;
  void* data;
  size_t ctrl_len = 0;
  
  memset(&ctrl_hdr, 0, sizeof(sstp_control_header_t));
  ctrl_hdr.message_type = msg_type;
  ctrl_hdr.num_attributes = 1;

  ctrl_len = sizeof(sstp_control_header_t) + len;
  
  data = xmalloc(ctrl_len);
  memcpy(data, attrs, len);

  send_sstp_packet(tls, SSTP_CONTROL_PACKET, data, ctrl_len);

  free(data);
}


void init_sstp(gnutls_session_t* tls)
{
  sstp_attribute_header_t attr_hdr;
  uint16_t protocol_id;
  char *buf;

  size_t len = sizeof(sstp_attribute_header_t) + sizeof(uint16_t);
  void* data = xmalloc(len);
  
  protocol_id = SSTP_ENCAPSULATED_PROTOCOL_PPP;
  attr_hdr.reserved = 0;
  attr_hdr.attribute_id = SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID;
  attr_hdr.packet_length = len;
  
  memcpy(data, &attr_hdr, len);
  memcpy(data + sizeof(sstp_attribute_header_t), &protocol_id, sizeof(uint16_t));

  send_sstp_control_packet(tls, SSTP_MSG_CALL_CONNECT_REQUEST, data, len);

  free(data);
  
  buf = sstp_recv(tls);
  free(buf);  
}

