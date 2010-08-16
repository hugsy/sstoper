#define _POSIX_SOURCE 1
#ifdef __linux__
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <sys/select.h>
#include <time.h>
#include <errno.h>
#include <pty.h>

#include "libsstp.h"
#include "sstpclient.h"


void generate_guid(char data[])
{
  /* details in http://download.microsoft.com/download/9/5/E/.../%5BMS-DTYP%5D.pdf */
  uint32_t data1, data4;
  uint16_t data2, data3;

  memset(data, 0, 39);
  srand (time (NULL));
  data1 = (rand() + 1) * (sizeof(uint32_t) * 8);
  data2 = (rand() + 1) * (sizeof(uint16_t) * 8);
  data3 = (rand() + 1) * (sizeof(uint16_t) * 8);
  data4 = (rand() + 1) * (sizeof(uint32_t) * 8);
  snprintf(data, 38, "{%x-%x-%x-%x}", data1, data2, data3, data4);

  if (cfg->verbose) xlog(LOG_INFO, "Using GUID %s\n", data);
}


int is_valid_header(void* recv_buf, ssize_t recv_len)
{
  sstp_header_t* header = (sstp_header_t*) recv_buf;
  
  return (header->version == SSTP_VERSION) && \
    (header->reserved==SSTP_DATA_PACKET || header->reserved==SSTP_CONTROL_PACKET) && \
    ntohs(header->length)==recv_len;
}


int is_control_packet(sstp_header_t* pkt_hdr)
{
  return (pkt_hdr->reserved & 0x01);
}


int https_session_negociation()
{
  ssize_t rbytes;
  char* buf;
  size_t recv_size;
  char guid[39];
  
  rbytes = -1;
  recv_size = gnutls_record_get_max_size(*tls);
  buf = (char*) xmalloc(recv_size);
  generate_guid(guid);
  
  /*
    SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1 
    SSTPCORRELATIONID: {F7FC0718-C386-4D9A-B529-973927075AA7}
    Content-Length: 18446744073709551615
    Host: vpn.coyote.looney
    ClientByPassHLAuth: True\r\n
    ClientHTTPCookie: 5d41402abc4b2a76b9719d911017c592\r\n
    SSTPVERSION: 1.0
  */
  
  snprintf(buf, recv_size,
	   "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
	   "SSTPCORRELATIONID: %s\r\n"
	   "Content-Length: %llu\r\n"
	   "Host: %s\r\n"
	   "\r\n",
	   guid,
	   __UNSIGNED_LONG_LONG_MAX__,
	   cfg->server);

  if (cfg->verbose) xlog(LOG_DEBUG, "Sending: %s\n", buf);

  sstp_send(buf, strlen(buf));
  
  memset(buf, 0, recv_size);
  rbytes = gnutls_record_recv (*tls, buf, recv_size);
      
  if (rbytes > 0)
    {
      xlog(LOG_INFO , "<-- %lu bytes\n", rbytes);
      if (cfg->verbose) xlog(LOG_DEBUG , "Received: %s\n", buf);
    }
  else if (rbytes == 0)
    {
      xlog(LOG_INFO , "!! Connection has been closed !!\n");
      return -1;
    }
  else 
    {
      xlog(LOG_ERROR, "gnutls_record_recv: %s\n", gnutls_strerror(rbytes));
      return -2;
    }

  if (strstr(buf, "HTTP/1.1 200") == NULL) 
    return -3;

  free(buf);
  return 0;
}


void sstp_send(void* data, size_t len)
{
  ssize_t sbytes;

  sbytes = gnutls_record_send (*tls, data, len);
  
  if (sbytes < 0)
    {
      xlog(LOG_ERROR, "gnutls_record_send: %s\n", gnutls_strerror(sbytes));
      exit(sbytes);
    }

  xlog(LOG_INFO, " --> %lu %s bytes\n", sbytes,
       is_control_packet((sstp_header_t*)data)?"control":"data");
  
}


void sstp_loop() 
{
  ssize_t rbytes;
  char* buf;
  size_t rbuf_max_size;
  fd_set msrd;
  int retcode;

  
  rbuf_max_size = gnutls_record_get_max_size(*tls);
 
  initialize_sstp();
   
  while(ctx->state != CLIENT_CALL_DISCONNECTED)
    {
      
      FD_ZERO(&msrd);
      FD_SET(0, &msrd);
      FD_SET(sockfd, &msrd);

      retcode = select(sockfd + 1, &msrd, NULL, NULL, NULL);
      
      if ( retcode == -1 )
	{
	  xlog(LOG_ERROR, "sstp_loop: select failed: %s\n", strerror(errno));
	  ctx->state = CLIENT_CALL_DISCONNECTED;
	  break;
	}

      if (FD_ISSET(0, &msrd)) 
	{
	  /* read from 0 and sstp_send to dest */
	  buf = (char*) xmalloc(rbuf_max_size);
	  rbytes = read(0, buf, rbuf_max_size);
	  send_sstp_data_packet(buf, rbytes);
	  free(buf);	  
	}
      
      if (FD_ISSET(sockfd, &msrd))
	{
	  /* sstp_read data from sockfd and write it to 1 */
	  buf = (char*) xmalloc(rbuf_max_size);
	  rbytes = gnutls_record_recv (*tls, buf, rbuf_max_size);
	  	  
	  if (rbytes < 0)
	    {
	      retcode = rbytes;
	      xlog(LOG_ERROR, "sstp_loop: gnutls_record_recv: %s\n", gnutls_strerror(rbytes));
	    }
	  else if (rbytes == 0) 
	    xlog(LOG_INFO, "sstp_loop: EOF\n");
	  else 
	    {
	      if (cfg->verbose)
		xlog(LOG_INFO,"<--  %lu %s bytes\n", rbytes,
		     is_control_packet((sstp_header_t*)buf)?"control":"data");
	      retcode = sstp_decode(buf, rbytes);
	    }
	  
	  free(buf);

	  if (retcode < 0) break;
	}
    }

  free(ctx);
}


int sstp_decode(void* recv_buf, ssize_t sstp_pkt_len)
{
  sstp_header_t* sstp_hdr;
  int ctrl_pkt;
  int retcode;
 
  if (!is_valid_header(recv_buf, sstp_pkt_len))
    {
      xlog(LOG_ERROR, "SSTP packet has invalid header\n");
      return -1;
    }
    

  sstp_hdr = (sstp_header_t*) recv_buf;
  ctrl_pkt = is_control_packet(sstp_hdr);
  
  if (cfg->verbose)
      xlog(LOG_INFO, "\t-> %s packet\n", ctrl_pkt?"Control":"Data");

  sstp_pkt_len -= sizeof(sstp_header_t);
  if (sstp_pkt_len <= 0)
    {
      xlog(LOG_ERROR, "SSTP packet has incorrect length.\n");
      return -1;
    }
  
  
  if (ctrl_pkt)
    {
      sstp_control_header_t* ctrl_hdr;
      uint16_t ctrl_type, ctrl_num_attr;
      void* first_attr_ptr;

      ctrl_hdr = (sstp_control_header_t*) (recv_buf + sizeof(sstp_header_t));
      ctrl_type = ntohs( ctrl_hdr->message_type );
      ctrl_num_attr = ntohs( ctrl_hdr->num_attributes );
      first_attr_ptr = (void*)(ctrl_hdr) + sizeof(sstp_control_header_t);
      
      sstp_pkt_len -= sizeof(sstp_control_header_t);
      if (sstp_pkt_len < 0)
	{
	  xlog(LOG_ERROR, "SSTP control packet has invalid size\n");
	  return -1;
	}
      

      if (cfg->verbose)
	xlog(LOG_INFO, "\t-> type:%x num_attr:%x\n", ctrl_type, ctrl_num_attr);

      
      switch (ctrl_type)
	{
	case SSTP_MSG_CALL_CONNECT_ACK:
	  retcode = sstp_decode_attributes(ctrl_num_attr, first_attr_ptr, sstp_pkt_len);
	  if (retcode < 0) return -1;

	  retcode = sstp_fork();
	  if (retcode < 0) return -1;
	  break;
	    
	case SSTP_MSG_CALL_CONNECT_NAK:
	  xlog(LOG_ERROR, "Server refused connection\n");
	  retcode = sstp_decode_attributes(ctrl_num_attr, first_attr_ptr, sstp_pkt_len);
	  if (retcode < 0) return -1;

	  if ( (ctx->state & CLIENT_CONNECT_REQUEST_SENT) && (ctx->retry) )
	    {
	      if (cfg->verbose) xlog(LOG_INFO, "Retrying ...\n");
	      ctx->negociation_timer.tv_sec = SSTP_NEGOCIATION_TIMER;
	      ctx->retry--;
	      initialize_sstp();
	      break;	      
	    }

	  break;
	  
	case SSTP_MSG_CALL_ABORT:
	  retcode = sstp_decode_attributes(ctrl_num_attr, first_attr_ptr, sstp_pkt_len);
	  if (retcode < 0) return -1;

	  break;
	  
	case SSTP_MSG_CALL_DISCONNECT:
	  retcode = sstp_decode_attributes(ctrl_num_attr, first_attr_ptr, sstp_pkt_len);
	  if (retcode < 0) return -1;

	  send_sstp_control_packet(SSTP_MSG_CALL_DISCONNECT_ACK, NULL, 0, 0);
	  ctx->state = CLIENT_CALL_DISCONNECTED;
	  break;
	  
	  
	  /*
	   * Client SHOULD NEVER receive teh following message.
	   * If so, close (dirtiliy) the client.
	   */
	case SSTP_MSG_CALL_CONNECT_REQUEST:
	case SSTP_MSG_CALL_DISCONNECT_ACK:
	default :
	  xlog(LOG_ERROR, "Client cannot unhandle type %#x\n", ctrl_type);
	  ctx->state = CLIENT_CALL_DISCONNECTED;
	  return -1;	  
	}
      
    }
  else 
    {
      void* data;
      int data_len;

      data = recv_buf + sizeof(sstp_header_t);
      data_len = sstp_pkt_len - sizeof(sstp_header_t);      
      retcode = write(1, data, data_len);

      if (retcode < 0) 
	{
	  xlog(LOG_ERROR, "write: %s\n", strerror(retcode));
	  return -1;
	}
    }

  return 0;
}


int sstp_decode_attributes(uint16_t attrnum, void* data, ssize_t bytes_to_read) 
{
  void* attr_ptr;
  int retcode;
  
  attr_ptr = data;
  retcode = 0;

  
  /* attributes parsing */
  while (attrnum) 
    {
      sstp_attribute_header_t* ctrl_attr_hdr;
      void* ctrl_attr_data;
      uint8_t attr_id;
      uint16_t attr_len;
      
      ctrl_attr_hdr = (sstp_attribute_header_t*) attr_ptr;
      attr_id = ctrl_attr_hdr->attribute_id;
      attr_len = ntohs( ctrl_attr_hdr->packet_length );
      ctrl_attr_data = (attr_ptr + sizeof(sstp_attribute_header_t));

      bytes_to_read -= attr_len;
      
      if (bytes_to_read < 0) 
	{
	  xlog(LOG_ERROR, "Trying to read at incorrect offset in control packet.\n");
	  return -1;
	}
            
      if (cfg->verbose)
	xlog(LOG_INFO, "\t\t--> id:%#x len:%d\n", attr_id, attr_len);
      
      switch (attr_id)
	{
	case SSTP_ATTRIB_NO_ERROR:
	  printf("SSTP_ATTRIB_NO_ERROR\n");
	  break;

	case SSTP_ATTRIB_STATUS_INFO:
	  if (cfg->verbose)
	    xlog(LOG_INFO, "\t\t--> SSTP_ATTRIB_STATUS_INFO\n");

	  retcode = get_status_info(ctrl_attr_data, attr_len);
	  break;
	  
	case SSTP_ATTRIB_CRYPTO_BINDING:
	  printf("SSTP_ATTRIB_CRYPTO_BINDING\n");
	  break;
	  
	case SSTP_ATTRIB_CRYPTO_BINDING_REQ:
	  if (cfg->verbose)
	    xlog(LOG_INFO, "\t\t--> SSTP_ATTRIB_CRYPTO_BINDING_REQ\n");

	  retcode = set_crypto_binding(ctrl_attr_data);
	  break;

	case SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID:
	  xlog(LOG_ERROR, "SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID: ");
	default:
	  xlog(LOG_ERROR, "Unhandled attribute %#x\n", attr_id);
	  retcode = -1;
	}

      if (retcode < 0) break;
            
      attr_ptr += attr_len;
      attrnum--;
    }
  
  return retcode;
}


void send_sstp_packet(int type, void* data, size_t len)
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
  
  sstp_send(pkt, total_length);
  
  free(pkt);
}


void send_sstp_data_packet(void* data, size_t len) 
{
  send_sstp_packet(SSTP_DATA_PACKET, data, len);
}


void send_sstp_control_packet(uint8_t msg_type, sstp_attribute_header_t* attrs,
			      uint16_t attrs_num, size_t attrs_len)
{
  sstp_control_header_t ctrl_hdr;
  size_t ctrl_hdr_len;
  size_t ctrl_len;
  void* data;

  if (attrs == NULL && attrs_num != 0)
    {
      xlog(LOG_ERROR, "No attribute specified. Cannot send message.\n");
      return;
    } 
  
  ctrl_hdr_len = sizeof(sstp_control_header_t);
  ctrl_len = ctrl_hdr_len + attrs_len;
  
  memset(&ctrl_hdr, 0, sizeof(sstp_control_header_t));
  
  ctrl_hdr.message_type = htons(msg_type);
  ctrl_hdr.num_attributes = htons(attrs_num);
  
  data = xmalloc(ctrl_len);
  memcpy(data, &ctrl_hdr, ctrl_hdr_len);
  if (attrs_num)
    memcpy(data + ctrl_hdr_len, attrs, attrs_len);

  send_sstp_packet(SSTP_CONTROL_PACKET, data, ctrl_len);

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


void initialize_sstp()
{
  uint16_t attr_data;
  int attr_len;
  sstp_attribute_t* attribute;

  /* setup sstp context */
  ctx = (sstp_context_t*) xmalloc(sizeof(sstp_context_t));
  ctx->retry = 5;
  ctx->state = CLIENT_CALL_DISCONNECTED;
  ctx->negociation_timer.tv_sec = SSTP_NEGOCIATION_TIMER;

  /* send SSTP_MSG_CALL_CONNECT_REQUEST message */
  attribute = NULL;
  attr_data = htons(SSTP_ENCAPSULATED_PROTOCOL_PPP);
  attribute = create_attribute(SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID,
			       &attr_data, sizeof(uint16_t));  
  send_sstp_control_packet(SSTP_MSG_CALL_CONNECT_REQUEST, 
			   attribute->data, 1, attribute->length);

  free(attribute->data);
  free(attribute);

  /* set alarm and change state */
  alarm(ctx->negociation_timer.tv_sec);
  ctx->state = CLIENT_CONNECT_REQUEST_SENT;
}


int set_crypto_binding(void* data)
{
  sstp_attribute_crypto_bind_req_t* req;
  uint8_t hash;
  int i;

  /* disable negociation timer */
  alarm(0);

  /* check state */
  if (ctx->state != CLIENT_CONNECT_REQUEST_SENT)
    {
      xlog(LOG_ERROR, "Incorrect message for this state\n");
      if (cfg->verbose)
	xlog(LOG_ERROR, "Current state: %#x\nExpected: %#x\n",
	     ctx->state, CLIENT_CONNECT_REQUEST_SENT);
      return -1;
    }
  
  /* setting crypto properties */
  req = (sstp_attribute_crypto_bind_req_t*) data;
  hash = ntohl(req->hash_bitmask);

  if ( !(hash & CERT_HASH_PROTOCOL_SHA1) && !(hash & CERT_HASH_PROTOCOL_SHA256))
    {
      xlog(LOG_ERROR, "Unknown hash algorithm %#x\n", hash);
      return -1;
    }
	  	  
  if (hash & CERT_HASH_PROTOCOL_SHA1)
    ctx->hash_algorithm = CERT_HASH_PROTOCOL_SHA1;
  else if (hash &CERT_HASH_PROTOCOL_SHA256)
    ctx->hash_algorithm = CERT_HASH_PROTOCOL_SHA256;
  
  if (cfg->verbose)
    xlog(LOG_INFO, "\t\t--> hash: %#x\n", hash);
	  
  if (cfg->verbose) xlog(LOG_INFO, "\t\t--> nonce: ");

  for (i=0; i<4; i++)
    {
      ctx->nonce[i] = ntohl(req->nonce[i]);
      if (cfg->verbose)
	xlog(LOG_INFO,"%#x %c",ctx->nonce[i],(i==3)?'\n':' ');
    }
  
  ctx->state = CLIENT_CONNECT_ACK_RECEIVED;
  return 0;
}


int get_status_info(void* data, uint16_t attr_len)
{
  sstp_attribute_status_info_t* info;
  uint8_t attrib_id;
  uint32_t status;
  int rbytes;

  info = (sstp_attribute_status_info_t*) data;
  attrib_id = ntohl(info->attrib_id);
  status = ntohl(info->status);

  /* show attribute */
  xlog(LOG_INFO, "\t\t--> attribute id: %#x\n", attrib_id);
  xlog(LOG_INFO, "\t\t--> status: %#x\n", status);

  if (ctx->state != CLIENT_CONNECT_REQUEST_SENT)
    return 0;
  
  /* attrib_value is at most 64 bytes (ie full attr len <= 64 + 12 bytes)*/
  rbytes = sizeof(sstp_attribute_header_t) + 2*sizeof(uint32_t);

  while (rbytes < (64+12) && rbytes < attr_len)
    {
      uint32_t attrib_value;
      attrib_value = ntohl(*((uint32_t*)data + rbytes));
      xlog(LOG_INFO, "\t\t--> attribute value: %#.4x\n", attrib_value);
      rbytes += sizeof(uint32_t);
    }
  
  return 0;
}


int sstp_fork() 
{
  /* shamely copied from ssltunnel */
  
  pid_t ppp_pid;
  int retcode, amaster, aslave, i;
  struct termios pty;
  const char pppd_path[] = "/usr/sbin/pppd";
  char *pppd_args[128];

  
  i = 0;
  pppd_args[i++] = "pppd";

  pppd_args[i++] = "nodetach";
  /* pppd_args[i++] = "local"; */
  /* pppd_args[i++] = "mppe-stateful"; */
  
  /* pppd_args[i++] = "noauth"; */

  /* pppd_args[i++] = "mtu";  */
  /* pppd_args[i] = xmalloc(10); */
  /* snprintf(pppd_args[i],10,"%d",gnutls_record_get_max_size(*tls)-sizeof(sstp_header_t));i++; */
  /* pppd_args[i++] = "mru";  */
  /* pppd_args[i] = xmalloc(10); */
  /* snprintf(pppd_args[i],10,"%d",gnutls_record_get_max_size(*tls)-sizeof(sstp_header_t));i++; */

  /* pppd_args[i++] = "remotename"; pppd_args[i++] = "test-sstp"; */
  /* pppd_args[i++] = "name"; pppd_args[i++] = "test-sstp"; */
  /* pppd_args[i++] = "user"; pppd_args[i++] = "test-sstp"; */
  /* pppd_args[i++] = "name"; pppd_args[i++] = "test-sstp"; */
  /* pppd_args[i++] = "password"; pppd_args[i++] = "Hello1234";   */
  /* pppd_args[i++] = "remotename"; pppd_args[i++] = "DC-VPN-CA";   */
  /* pppd_args[i++] = "bsdcomp"; pppd_args[i++] = "15"; */
  /* pppd_args[i++] = "crtscts"; */
  pppd_args[i++] = "lock";
  pppd_args[i++] = "logfile";   pppd_args[i++] = "/home/hugsy/code/sstpclient/misc/pppd_debug";
  /* pppd_args[i++] = "default-asyncmap"; */
  pppd_args[i++] = "debug";
  pppd_args[i++] = "sync";
  
  pppd_args[i++] = NULL;
  
  memset(&pty, 0, sizeof(struct termios));
  pty.c_cc[VMIN] = 1;
  pty.c_cc[VTIME] = 0;
  pty.c_cflag |= B9600;

  retcode = openpty(&amaster, &aslave, NULL, &pty, NULL);
  if (retcode < 0)
    {
      xlog (LOG_ERROR, "openpty failed: %s", strerror(errno));
      return -1;
    }

  
  ppp_pid = fork();
  
  if (ppp_pid > 0)
    {
      dup2(amaster, 0);
      dup2(amaster, 1);
      
      if (aslave > 2) close(aslave);
      if (amaster > 2) close(amaster);
    
      return ppp_pid;
    }
  
  else if (ppp_pid == 0) 
    {
      close(sockfd);

      dup2(aslave, 0);
      dup2(aslave, 1);

      if (aslave > 2) close (aslave);
      if (amaster > 2) close (amaster);

      if (cfg->verbose)
	{
	  xlog(LOG_INFO, "Preparing to fork %s with options:\n\t", pppd_path);
	  for (i=0; i<128; i++)
	    {
	      if (pppd_args[i] == NULL) break;
	      xlog(LOG_INFO, "%s ", pppd_args[i]);
	    }
	  xlog(LOG_INFO, "\n");
	}
      
      if (execv (pppd_path , pppd_args))
	{
	  xlog (LOG_ERROR, "execv failed: %s", strerror(errno));
	  exit(1);
	}

      return 0;
    }
  
  else
    {
      xlog (LOG_ERROR, "fork failed: %s", strerror(errno));
      return -1;
    }
}
