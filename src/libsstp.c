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
#include <fcntl.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "libsstp.h"
#include "sstpclient.h"


void generate_guid(char data[])
{
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
  
  return (header->version == SSTP_VERSION) \
    && (header->reserved==SSTP_DATA_PACKET || header->reserved==SSTP_CONTROL_PACKET) \
    && ntohs(header->length)==recv_len;
}


int is_control_packet(sstp_header_t* packet_header)
{
  return (packet_header->reserved & 0x01);
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
      xlog(LOG_INFO , "Connection has been closed by beer.\n");
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


void initialize_sstp()
{
  uint16_t attribute_data;
  int i;
  void* attribute;
  size_t attribute_len;
  
  /* initialize sstp context */
  ctx = (sstp_context_t*) xmalloc(sizeof(sstp_context_t));
  ctx->retry = 5;
  ctx->state = CLIENT_CALL_DISCONNECTED;
  ctx->negociation_timer.tv_sec = SSTP_NEGOCIATION_TIMER;
  ctx->pppd_pid = -1;
  for (i=0; i<8; i++) ctx->nonce[i] = 0x0a0a0a0a;
  for (i=0; i<8; i++) ctx->cmac[i] = 0x0b0b0b0b;
  for (i=0; i<8; i++) ctx->cmac[i] = 0x0c0c0c0c;

  
  /* send SSTP_MSG_CALL_CONNECT_REQUEST message */
  attribute_data = htons(SSTP_ENCAPSULATED_PROTOCOL_PPP);
  attribute_len = sizeof(sstp_attribute_header_t) + sizeof(uint16_t);
  attribute = create_attribute(SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID,
			       (void*)&attribute_data, sizeof(uint16_t));

  
  send_sstp_control_packet(SSTP_MSG_CALL_CONNECT_REQUEST, attribute,
			   1, attribute_len);

  free(attribute);

  
  /* set alarm and change state */
  alarm(ctx->negociation_timer.tv_sec);
  ctx->state = CLIENT_CONNECT_REQUEST_SENT;
 
}


void sstp_loop() 
{
  ssize_t rbytes;
  void* buf;
  size_t rbuf_max_size;
  fd_set msrd;
  int retcode;

  
  read_max_size = gnutls_record_get_max_size(*tls);
 
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
	  buf = xmalloc(read_max_size);
	  rbytes = read(0, buf, read_max_size);
	  send_sstp_data_packet(buf, rbytes);
	  free(buf);
	}
      
      if (FD_ISSET(sockfd, &msrd))
	{
	  /* sstp_read data from sockfd and write it to 1 */
	  buf = xmalloc(read_max_size);
	  rbytes = gnutls_record_recv (*tls, buf, read_max_size);
	  	  
	  if (rbytes < 0)
	    {
	      retcode = rbytes;
	      xlog(LOG_ERROR, "sstp_loop: gnutls_record_recv: %s\n", gnutls_strerror(rbytes));
	    }
	  
	  else if (rbytes == 0) 
	    {
	      xlog(LOG_INFO, "sstp_loop: EOF\n");
	    }
	  
	  else 
	    {
	      if (cfg->verbose)
		xlog(LOG_INFO,"<--  %lu bytes\n", rbytes);

	      retcode = sstp_decode(buf, rbytes);
	    }
	  
	  free(buf);

	  if (retcode < 0) break;
	}
    }

  free(ctx);
}


void sstp_send(void* data, size_t data_length)
{
  ssize_t sbytes;

  sbytes = gnutls_record_send (*tls, data, data_length);
  
  if (sbytes < 0)
    {
      xlog(LOG_ERROR, "gnutls_record_send: %s\n", gnutls_strerror(sbytes));
      exit(sbytes);
    }

  xlog(LOG_INFO, " --> %lu bytes\n", sbytes);
  
}


void send_sstp_packet(uint8_t type, void* data, size_t data_length)
{
  sstp_header_t sstp_header;
  size_t total_length;
  void *packet = NULL;

  total_length = sizeof(sstp_header_t) + data_length;
  memset(&sstp_header, 0, sizeof(sstp_header_t));
  
  sstp_header.version = SSTP_VERSION;
  sstp_header.reserved = type;
  sstp_header.length = htons(total_length); 
 
  packet = xmalloc(total_length);
  
  memcpy(packet, &sstp_header, sizeof(sstp_header_t));
  memcpy(packet + sizeof(sstp_header_t), data, data_length);
  
  sstp_send(packet, total_length);
  
  free(packet);
}


int sstp_decode(void* rbuffer, ssize_t sstp_length)
{
  sstp_header_t* sstp_header;
  int is_control;
  int retcode;
 
  if (!is_valid_header(rbuffer, sstp_length))
    {
      xlog(LOG_ERROR, "SSTP packet has invalid header\n");
      xlog(LOG_ERROR, "Dropping this packet\n" );
      return 0;
    }
    

  sstp_header = (sstp_header_t*) rbuffer;
  is_control = is_control_packet(sstp_header);
  
  if (cfg->verbose)
    xlog(LOG_INFO, "\t-> %s packet\n", is_control ? "Control" : "Data");

  sstp_length -= sizeof(sstp_header_t);
  if (sstp_length <= 0)
    {
      xlog(LOG_ERROR, "SSTP packet has incorrect length.\n");
      return -1;
    }
  
  
  if (is_control)
    {
      sstp_control_header_t* ctrl_hdr;
      uint16_t ctrl_type, ctrl_num_attr;
      void* first_attr_ptr;

      ctrl_hdr = (sstp_control_header_t*) (rbuffer + sizeof(sstp_header_t));
      ctrl_type = ntohs( ctrl_hdr->message_type );
      ctrl_num_attr = ntohs( ctrl_hdr->num_attributes );
      first_attr_ptr = (void*)(ctrl_hdr) + sizeof(sstp_control_header_t);

      
      /* checking control header */
      sstp_length -= sizeof(sstp_control_header_t);
      if (sstp_length < 0)
	{
	  xlog(LOG_ERROR, "SSTP control packet has invalid size\n");
	  return -1;
	}

      if (!ctrl_type || ctrl_type > SSTP_MSG_ECHO_RESPONSE)
	{
	  xlog(LOG_ERROR, "Incorrect control packet\n");
	  return -1;  
	}
      
      
      /* parsing control header */
      if (cfg->verbose)
	{
	  xlog(LOG_INFO, "\t-> type: %s (%#x)\n", control_messages_types_str[ctrl_type], ctrl_type);
	  xlog(LOG_INFO, "\t-> num_attr:%x\n", ctrl_num_attr);
	}
      
      switch (ctrl_type)
	{
	case SSTP_MSG_CALL_CONNECT_ACK:
	  retcode = sstp_decode_attributes(ctrl_num_attr, first_attr_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  retcode = sstp_fork();
	  if (retcode < 0) return -1;
	  ctx->pppd_pid = retcode;
	  if (cfg->verbose)
	    xlog (LOG_INFO, "pppd forked as %d\n", ctx->pppd_pid);

	  break;
	    
	case SSTP_MSG_CALL_CONNECT_NAK:
	  xlog(LOG_ERROR, "Server refused connection\n");
	  retcode = sstp_decode_attributes(ctrl_num_attr, first_attr_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  if ( ctx->state==CLIENT_CONNECT_REQUEST_SENT && ctx->retry )
	    {
	      if (cfg->verbose) xlog(LOG_INFO, "Retrying ...\n");
	      ctx->negociation_timer.tv_sec = SSTP_NEGOCIATION_TIMER;
	      ctx->retry--;
	      initialize_sstp();
	      break;	      
	    }

	  break;
	  
	case SSTP_MSG_CALL_ABORT:
	  retcode = sstp_decode_attributes(ctrl_num_attr, first_attr_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  break;
	  
	case SSTP_MSG_CALL_DISCONNECT:
	  retcode = sstp_decode_attributes(ctrl_num_attr, first_attr_ptr, sstp_length);
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
	  xlog(LOG_ERROR, "Client cannot handle type %#x\n", ctrl_type);
	  ctx->state = CLIENT_CALL_DISCONNECTED;
	  return -1;
	}
      
    }
  else 
    {
      int i;
      size_t attribute_len;
      void* data_ptr;
      void* attribute;
      sstp_attribute_crypto_bind_t crypto_settings;
      
      data_ptr = rbuffer + sizeof(sstp_header_t);
      
      /* if PPP-CHAP is successful, send SSTP_MSG_CALL_CONNECTED */
      if ( ntohs(*((uint16_t*)data_ptr)) == 0xc223 &&
	   (*(uint8_t*)(data_ptr + 2)) == 0x03 )
	{

	  crypto_settings.hash_bitmask = htonl(ctx->hash_algorithm);
	  for (i=0; i<8; i++) crypto_settings.nonce[i] = htonl(ctx->nonce[i]);
	  for (i=0; i<8; i++) crypto_settings.certhash[i] = htonl(ctx->certhash[i]);
	  for (i=0; i<8; i++) crypto_settings.cmac[i] = htonl(ctx->cmac[i]);
	  
	  attribute = create_attribute(SSTP_ATTRIB_CRYPTO_BINDING, (void*)&crypto_settings,
				  sizeof(sstp_attribute_crypto_bind_t));
	  attribute_len = sizeof(sstp_attribute_header_t) + sizeof(sstp_attribute_crypto_bind_t);
	  
	  send_sstp_control_packet(SSTP_MSG_CALL_CONNECTED, &attribute, 1,attribute_len);

	  free(attribute);
	}

      retcode = write(1, data_ptr, sstp_length);

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


      /* checking attribute header*/
      bytes_to_read -= attr_len;
      if (bytes_to_read < 0) 
	{
	  xlog(LOG_ERROR, "Trying to read at incorrect offset in control packet.\n");
	  return -1;
	}
      if (attr_id > SSTP_ATTRIB_CRYPTO_BINDING_REQ)
	{
	  xlog(LOG_ERROR, "Incorrect attribute id.\n");
	  return -1;
	}

      
      /* parsing attribute header */
      if (cfg->verbose)
	{
	  xlog(LOG_INFO, "\t\t--> attr_id:%s (%#x)\n",attr_types_str[attr_id], attr_id);
	  xlog(LOG_INFO, "\t\t--> len:%d\n", attr_len);
	}
      
      switch (attr_id)
	{
	case SSTP_ATTRIB_NO_ERROR:
	  break;

	case SSTP_ATTRIB_STATUS_INFO:
	  retcode = attribute_status_info(ctrl_attr_data, attr_len);
	  break;
	  
	case SSTP_ATTRIB_CRYPTO_BINDING_REQ:
	  retcode = crypto_set_binding(ctrl_attr_data);
	  break;

	  /* cas a ne pas traiter */
	case SSTP_ATTRIB_CRYPTO_BINDING:
	case SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID:
	default:
	  xlog(LOG_ERROR, "Attribute ID %#x is not handled on client side.\n", attr_id);
	  retcode = -1;
	}

      if (retcode < 0) break;
            
      attr_ptr += attr_len;
      attrnum--;
    }
  
  return retcode;
}


void send_sstp_data_packet(void* data, size_t len) 
{
  send_sstp_packet(SSTP_DATA_PACKET, data, len);
}


void send_sstp_control_packet(uint16_t msg_type, void* attribute,
			      uint16_t attribute_number, size_t attribute_len)
{
  sstp_control_header_t control_header;
  size_t control_length;
  void *data, *data_ptr, *attr_ptr;

  if (attribute == NULL && attribute_number != 0)
    {
      xlog(LOG_ERROR, "No attribute specified. Cannot send message.\n");
      return;
    } 
  
  control_length = sizeof(sstp_control_header_t) + attribute_len; 
  memset(&control_header, 0, sizeof(sstp_control_header_t));

  /* setting control header */
  control_header.message_type = htons(msg_type);
  control_header.num_attributes = htons(attribute_number);

  /* filling control with attributes */
  data = xmalloc(control_length);
  memcpy(data, &control_header, sizeof(sstp_control_header_t));

  attr_ptr = attribute;
  data_ptr = data + sizeof(sstp_control_header_t);
  
  while (attribute_number)
    {
      sstp_attribute_header_t* cur_attr = (sstp_attribute_header_t*)attr_ptr;    
      memcpy(data_ptr, attribute, cur_attr->packet_length);

      attr_ptr += cur_attr->packet_length;
      data_ptr += cur_attr->packet_length;
      attribute_number--;
    }
    
  /* yield to lower */
  send_sstp_packet(SSTP_CONTROL_PACKET, data, control_length);

  free(data);
}


void* create_attribute(uint8_t attribute_id, void* data, size_t data_length)
{
  sstp_attribute_header_t attribute_header;
  size_t attribute_length;
  void* attribute;
  
  if (!data) return NULL;

  attribute_length = sizeof(sstp_attribute_header_t) + data_length;
  attribute = xmalloc(attribute_length);
  
  attribute_header.reserved = 0;
  attribute_header.attribute_id = attribute_id;
  attribute_header.packet_length = htons(attribute_length);
  
  memcpy(attribute, &attribute_header, sizeof(sstp_attribute_header_t));
  memcpy(attribute + sizeof(sstp_attribute_header_t), data, data_length);
  
  return attribute;
}

int crypto_set_certhash()
{
  int fd, i, j;
  ssize_t rbytes;
  char buf[1024];
  unsigned char d[32];
  
  fd = open(cfg->ca_file, O_RDONLY);
  if (fd == -1)
    {
      perror("crypto_set_certhash: open");
      return -1;
    } 

  if (ctx->hash_algorithm == CERT_HASH_PROTOCOL_SHA1)
    {
      SHA_CTX c;
      SHA1_Init(&c);
      while ( (rbytes=read(fd, buf, 1024)) > 0)
	SHA1_Update(&c, buf, rbytes);
      SHA1_Final(d, &c);
    }
  else if (ctx->hash_algorithm == CERT_HASH_PROTOCOL_SHA256)
    {
      SHA256_CTX c;
      SHA256_Init(&c);
      while ( (rbytes=read(fd, buf, 1024)) > 0)
	SHA256_Update(&c, buf, rbytes);
      SHA256_Final(d, &c);
    }
  else 
    {
      /* cannot be here */
      exit(1);
    }

  close(fd);
  
  for (i=0, j=0; j<256; i++, j += sizeof(uint32_t))
    ctx->certhash[i] = *(uint32_t*)(d+j);

  return 0;
}


int crypto_set_binding(void* data)
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

  /* choose strongest algorithm */
  if (hash & CERT_HASH_PROTOCOL_SHA256)
    {
      ctx->hash_algorithm = CERT_HASH_PROTOCOL_SHA256;
      if (cfg->verbose)
	xlog(LOG_INFO, "\t\t--> hash algo: CERT_HASH_PROTOCOL_SHA256\n");
    }
    
  else if (hash & CERT_HASH_PROTOCOL_SHA1)
    {
      ctx->hash_algorithm = CERT_HASH_PROTOCOL_SHA1;
      if (cfg->verbose)
	xlog(LOG_INFO, "\t\t--> hash algo: CERT_HASH_PROTOCOL_SHA1\n");
    }
  else 
    {
      xlog(LOG_ERROR, "Unimplemented protocol.\n");
      return -1;
    }
    
  if (cfg->verbose) xlog(LOG_INFO, "\t\t--> nonce: ");
  for (i=0; i<8; i++)
    {
      ctx->nonce[i] = ntohl((uint32_t)req->nonce[i]);
      if (cfg->verbose)
	xlog(LOG_INFO,"%#x%c",ctx->nonce[i],(i==7)?'\n':' ');
    }

  /* compute ca file hash with chosen algorithm */
  if (crypto_set_certhash() < 0)
    return -1;
  
  /* change client state */
  ctx->state = CLIENT_CONNECT_ACK_RECEIVED;
  return 0;
}


int attribute_status_info(void* data, uint16_t attr_len)
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
  pid_t ppp_pid;
  int retcode, amaster, aslave, i;
  struct termios pty;
  char *pppd_path;
  char *pppd_args[128];

  
  pppd_path = cfg->pppd_path;
  
  i = 0;
  pppd_args[i++] = "pppd"; 
  pppd_args[i++] = "nodetach";
  pppd_args[i++] = "local";
  pppd_args[i++] = "nodefaultroute";
  pppd_args[i++] = "9600"; 
  pppd_args[i++] = "sync"; pppd_args[i++] = "refuse-eap";
  
  pppd_args[i++] = "user"; pppd_args[i++] = cfg->username;
  pppd_args[i++] = "password"; pppd_args[i++] = cfg->password;

  if (cfg->logfile != NULL) 
    {
      pppd_args[i++] = "logfile";   pppd_args[i++] = cfg->logfile;
      pppd_args[i++] = "debug";
    }

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
     
      if (execv (pppd_path, pppd_args) == -1)
	{
	  xlog (LOG_ERROR, "execv failed: %s", strerror(errno));
	  return -1;
	}
    }

  else 
    {
      xlog (LOG_ERROR, "sstp_fork: %s", strerror(errno));
      return -1;
    }

  return -1;
}

