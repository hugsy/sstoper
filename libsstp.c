#include <gnutls/gnutls.h>
#include <string.h>
#include <stdio.h>
#include "libsstp.h"



int is_control_packet(sstp_header_t* pkt_hdr)
{
  return (pkt_hdr->reserved & 1);
}


void send_sstp_packet(gnutls_session_t* tls, void* data, int len, int type)
{
  sstp_header_t pkt_hdr;
  int total_length;

  total_length = sizeof(sstp_header_t) + len;
  memset(&pkt_hdr, 0, sizeof(sstp_header_t));
  
  pkt_hdr.version = 1;
  pkt_hdr.reserved = type;
  pkt_hdr.length = total_length;
  pkt_hdr.data = data;

  printf("Sending %d bytes\n", total_length);
  gnutls_record_send (*tls, &pkt_hdr, total_length);
}


void send_sstp_data_packet(gnutls_session_t* tls, char* data, int len) 
{
  send_sstp_packet(tls, (void*)data, len, SSTP_DATA_PACKET); 
}


void send_sstp_control_packet(gnutls_session_t* tls, sstp_attribute_header_t* attrs,
			      int len, uint8_t msg_type)
{
  sstp_control_header_t ctrl_hdr;
  
  memset(&ctrl_hdr, 0, sizeof(sstp_control_header_t));
  ctrl_hdr.message_type = msg_type;
  ctrl_hdr.num_attributes = 1;

  send_sstp_packet(tls, (void*)attrs, len + sizeof(sstp_control_header_t), SSTP_CONTROL_PACKET);
}


void init_sstp(gnutls_session_t* tls)
{
  sstp_attribute_header_t attr_hdr;
  uint16_t protocol_id;
  char buf[1024];
  int rbytes = -1;

  protocol_id = SSTP_ENCAPSULATED_PROTOCOL_PPP;
  attr_hdr.reserved = 0;
  attr_hdr.attribute_id = SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID;
  attr_hdr.packet_length = sizeof(sstp_attribute_header_t) + sizeof(uint16_t);
  attr_hdr.data = &protocol_id;

  send_sstp_control_packet(tls, &attr_hdr,
			   sizeof(sstp_attribute_header_t),
			   SSTP_MSG_CALL_CONNECT_REQUEST);
  
  memset(buf, 0, 1024);
  rbytes = gnutls_record_recv (*tls, buf, 1024-1);

  printf("received %d bytes\n", rbytes);
}

