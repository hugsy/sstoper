#define _POSIX_SOURCE 1

#include <gnutls/gnutls.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>        /* According to POSIX.1-2001 */

#include "libsstp.h"


extern int sockfd;


int is_control_packet(sstp_header_t* pkt_hdr)
{
  return (pkt_hdr->reserved & 1);
}

void sstp_send(gnutls_session_t* tls, void* data, size_t len)
{
  ssize_t sbytes;
  
  sbytes = -1;
  sbytes = gnutls_record_send (*tls, data, len);
  printf(" --> %lu bytes\n", len);
  
  if (sbytes < 0) 
    {
      gnutls_perror(sbytes);
      exit(1);
    }
}


void sstp_recv(gnutls_session_t* tls) 
{
  int rbytes;
  char* buf;

  while(1)
    {
      fd_set mselect;
      
      FD_ZERO(&mselect);
      FD_SET(0, &mselect);
      FD_SET(sockfd, &mselect);
      
      if (select(sockfd+1, &mselect,NULL,NULL,NULL)==-1)
	{
	  perror("select");
	  end_tls_session(tls, sockfd, 1);
	  exit(1);
	}
    
      if (FD_ISSET(0,&mselect)) break;
      if (FD_ISSET(sockfd,&mselect))
	{
	  rbytes = gnutls_record_check_pending(*tls);
	  if (rbytes == 0) break;
	  
	  printf("<--  %d bytes\n", rbytes);
	  
	  buf = (char*) xmalloc(rbytes);
	  rbytes = gnutls_record_recv (*tls, buf, rbytes);
	  
	  if (rbytes < 0)
	    {
	      gnutls_perror(rbytes);
	      free(buf);
	      exit(1);
	    }

	  sstp_decode(buf);
	}
    }
  
}


void sstp_decode(char* recv_buf)
{
  sstp_header_t* sstp_hdr;
  
  if (!valid_header(recv_buf)) return;

  sstp_hdr = (sstp_header_t*) recv_buf;

  if (is_control_packet(sstp_hdr)) 
    {
      sstp_control_header_t* ctrl_hdr;
      ctrl_hdr = get_sstp_control_header(recv_buf + sizeof(sstp_header_t));
      
      switch (ctrl_hdr->message_type)
	{
	case SSTP_MSG_CALL_CONNECT_ACK:
	  printf("acquitte\n"); break;
	  
	case SSTP_MSG_CALL_CONNECT_REQUEST:
	case SSTP_MSG_CALL_CONNECT_NAK:
	case SSTP_MSG_CALL_ABORT:
	case SSTP_MSG_CALL_DISCONNECT:
	case SSTP_MSG_CALL_DISCONNECT_ACK:
	default :
	  printf("%x\n", ctrl_hdr->message_type);
	}

      free(ctrl_hdr);
    }
}


int valid_header(void* recv_buf)
{
  sstp_header_t* header = (sstp_header_t*) recv_buf;
  
  return (header->version == 0x10) && \
    (header->reserved == 0x00 || header->reserved == 0x01);
}


void send_sstp_packet(gnutls_session_t* tls, int type, void* data, size_t len)
{
  sstp_header_t pkt_hdr;
  size_t sstp_hdr_len = sizeof(sstp_header_t);
  size_t total_length = sstp_hdr_len + len;
  void *pkt = NULL;

  memset(&pkt_hdr, 0, sstp_hdr_len);
  
  pkt_hdr.version = SSTP_VERSION;
  pkt_hdr.reserved = type;
  pkt_hdr.length = htons(total_length); 
 
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


sstp_control_header_t* get_sstp_control_header(void* recv_buf)
{
  sstp_control_header_t* ctrl_hdr; 

  ctrl_hdr = xmalloc(sizeof(sstp_control_header_t));
  ctrl_hdr->message_type = ntohs( *((uint16_t*)recv_buf) );
  ctrl_hdr->num_attributes  = ntohs( *((uint16_t*)recv_buf+sizeof(uint16_t)) );

  return ctrl_hdr;
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


sstp_attribute_t* create_attribute(uint8_t attr_id, void* attr_data, size_t attr_data_len)
{
  sstp_attribute_header_t attr_hdr;
  size_t sstp_attr_hdr_len;
  sstp_attribute_t* attr;
  void* data;
  
  if (!attr_data) return NULL;

  sstp_attr_hdr_len = sizeof(sstp_attribute_header_t);
  attr = xmalloc(sizeof(sstp_attribute_t));
  attr->length = sstp_attr_hdr_len + attr_data_len;
  attr->data = xmalloc(attr->length);
  
  attr_hdr.reserved = 0;
  attr_hdr.attribute_id = attr_id;
  attr_hdr.packet_length = htons(attr->length);
  
  memcpy(attr->data, &attr_hdr, sstp_attr_hdr_len);
  memcpy(attr->data + sstp_attr_hdr_len, attr_data, attr_data_len);
  
  return attr;
}


void init_sstp(gnutls_session_t* tls)
{
  uint16_t attr_data;
  int attr_len;
  sstp_attribute_t* attribute;

  attribute = NULL;
  attr_data = htons(SSTP_ENCAPSULATED_PROTOCOL_PPP);
  
  attribute = create_attribute(SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID,
			      &attr_data,
			      sizeof(uint16_t));

  send_sstp_control_packet(tls, SSTP_MSG_CALL_CONNECT_REQUEST,
			   attribute->data, attribute->length);

  free(attribute->data);
  free(attribute);

  /* main loop */
  sstp_recv(tls);
}

