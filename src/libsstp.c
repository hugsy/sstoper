#define _POSIX_SOURCE 1

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
#include <openssl/hmac.h>
#include <gnutls/x509.h>

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
  snprintf(data, 38, "{%.2X-%.2X-%.2X-%.2X}", data1, data2, data3, data4);

  if (cfg->verbose) xlog(LOG_INFO, "Using GUID %s\n", data);
}


void change_status(uint8_t status)
{
  ctx->state = status;

  if (cfg->verbose)
    xlog(LOG_INFO, "Client is now %s (%#x)\n", client_status_str[ctx->state], ctx->state);


}


int is_valid_header(void* recv_buf, ssize_t recv_len)
{
  sstp_header_t* header = (sstp_header_t*) recv_buf;
  
  if (header->version != SSTP_VERSION)
    {
      if (cfg->verbose)
	xlog(LOG_ERROR, "Invalid version (%#x)", header->version);
      return 0;
    }

  if (header->reserved!=SSTP_DATA_PACKET && header->reserved!=SSTP_CONTROL_PACKET)
    {
      if (cfg->verbose)
	xlog(LOG_ERROR, "Invalid packet type (%#x)\n", header->reserved);
      return 0;
    }

  /*
   * bug server sstp ou ppp (fixme)
   * le 1er packet ppp recu du serveur possede une taille de paquet differente de celle
   * annonce dans le header sstp -> test de la taille echoue 
   */
  if (ntohs(header->length) != recv_len)
    {
      if (cfg->verbose)
	xlog(LOG_ERROR, "Unmatching length: annonced %lu, received %lu\n", ntohs(header->length), recv_len);
      return 0;
    }

  return 1;
}


int is_control_packet(sstp_header_t* packet_header)
{
  return (packet_header->reserved == 0x01);
}


int https_session_negociation()
{
  ssize_t rbytes;
  char* buf;
  size_t read_size;
  char guid[39];

  rbytes = -1;
  read_size = gnutls_record_get_max_size(tls);
  buf = (char*) xmalloc(read_size);
  generate_guid(guid);
  
  rbytes = snprintf(buf, read_size,
		    "SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n"
		    "Host: AAAAAAAAAAAAAAAAAAAAAA.%s\r\n" // <-- bug : le hostname pas valide cote server 
		    "SSTPCORRELATIONID: %s\r\n"
		    "Content-Length: %llu\r\n"
		    "ClientBypassHLAuth: TRUE\r\n"
		    "Cookie: ClientHTTPCookie=1 OR 1=1;\r\n"
		    "\r\n",
		    cfg->server,
		    guid,
		    __UNSIGNED_LONG_LONG_MAX__);

  if (cfg->verbose) xlog(LOG_DEBUG, "Sending: %lu bytes\n%s\n", rbytes, buf);

  sstp_send(buf, rbytes);
  
  memset(buf, 0, read_size);
  rbytes = gnutls_record_recv (tls, buf, read_size);
      
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
  void* attribute;
  size_t attribute_len;
  
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
  change_status(CLIENT_CONNECT_REQUEST_SENT);

}


void sstp_loop()
{
  size_t read_max_size;
  fd_set msrd;
  int retcode;
  
  
  /* initialize sstp context */
  ctx = (sstp_context_t*) xmalloc(sizeof(sstp_context_t));
  ctx->retry = 5;
  ctx->state = CLIENT_CALL_DISCONNECTED;
  ctx->negociation_timer.tv_sec = SSTP_NEGOCIATION_TIMER;
  ctx->hello_timer.tv_sec = SSTP_NEGOCIATION_TIMER;
  ctx->pppd_pid = -1;

  read_max_size = gnutls_record_get_max_size(tls);
  

  /* start sstp negociation */
  initialize_sstp();


  while(ctx->state != CLIENT_CALL_DISCONNECTED)
    {
      FD_ZERO(&msrd);
      if (ctx->pppd_pid > 0)
	FD_SET(0, &msrd);
      FD_SET(sockfd, &msrd);   

      retcode = select(sockfd + 1, &msrd, NULL, NULL, NULL);
      
      if ( retcode == -1 )
	{
	  xlog(LOG_ERROR, "sstp_loop: select failed: %s\n", strerror(errno));
	  ctx->state = CLIENT_CALL_DISCONNECTED;
	  break;
	}

      if (ctx->pppd_pid > 0 && FD_ISSET(0, &msrd)) 
	{
	  /* read from 0 and sstp_send to dest */
	  char rbuffer[read_max_size];
	  ssize_t rbytes;
	  rbytes = read(0, rbuffer, read_max_size);
	  send_sstp_data_packet(rbuffer, rbytes);
	}
      
      if (FD_ISSET(sockfd, &msrd)) 
	{
	  /* sstp_read data from sockfd and write it to 1 */
	  char rbuffer[read_max_size];
	  ssize_t rbytes;

	  rbytes = gnutls_record_recv (tls, rbuffer, read_max_size);
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
	      xlog(LOG_INFO,"<--  %lu bytes\n", rbytes);
	      retcode = sstp_decode(rbuffer, rbytes);
	    }
	  
	  if (retcode < 0) break;
	}

    }
  
  free(ctx);
}


int sstp_decode(void* rbuffer, ssize_t sstp_length)
{
  sstp_header_t* sstp_header;
  int is_control, retcode;

  
  if (!is_valid_header(rbuffer, sstp_length))
    {
      xlog(LOG_ERROR, "SSTP packet has invalid header. Dropped\n");
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
      sstp_control_header_t* control_header;
      uint16_t control_type, control_num_attributes;
      void* attribute_ptr;

      
      control_header = (sstp_control_header_t*) (rbuffer + sizeof(sstp_header_t));
      control_type = ntohs( control_header->message_type );
      control_num_attributes = ntohs( control_header->num_attributes );
      attribute_ptr = (void*)(control_header) + sizeof(sstp_control_header_t);

      
      /* checking control header */
      sstp_length -= sizeof(sstp_control_header_t);
      if (sstp_length < 0)
	{
	  xlog(LOG_ERROR, "SSTP control packet has invalid size\n");
	  return -1;
	}

      if (!control_type || control_type > SSTP_MSG_ECHO_REPLY)
	{
	  xlog(LOG_ERROR, "Incorrect control packet\n");
	  return -1;  
	}
      
      
      /* parsing control header */
      if (cfg->verbose)
	{
	  xlog(LOG_INFO, "\t-> type: %s (%#.2x)\n", control_messages_types_str[control_type],
	       control_type);
	  xlog(LOG_INFO, "\t-> num_attr:%d\n", control_num_attributes);
	}
      
      switch (control_type)
	{
	case SSTP_MSG_CALL_CONNECT_ACK:
	  retcode = sstp_decode_attributes(control_num_attributes, attribute_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  retcode = sstp_fork();
	  if (retcode < 0) return -1;
	  
	  ctx->pppd_pid = retcode;
	  if (cfg->verbose)
	    xlog (LOG_INFO, "pppd forked as %d\n", ctx->pppd_pid);

	  break;
	    
	case SSTP_MSG_CALL_CONNECT_NAK:
	  if ( ctx->state==CLIENT_CONNECT_REQUEST_SENT ) return -1;
	  
	  retcode = sstp_decode_attributes(control_num_attributes, attribute_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  if ( ctx->retry ) 
	    {
	      if (cfg->verbose) xlog(LOG_INFO, "Retrying ... (%d/%d)\n",
				     5-ctx->retry, 5);
	      ctx->negociation_timer.tv_sec = SSTP_NEGOCIATION_TIMER;
	      ctx->retry--;
	      initialize_sstp();
	    }

	  break;
	  
	case SSTP_MSG_CALL_ABORT:
	  retcode = sstp_decode_attributes(control_num_attributes, attribute_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  break;
	  
	case SSTP_MSG_CALL_DISCONNECT:
	  retcode = sstp_decode_attributes(control_num_attributes, attribute_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  send_sstp_control_packet(SSTP_MSG_CALL_DISCONNECT_ACK, NULL, 0, 0);
	  ctx->state = CLIENT_CALL_DISCONNECTED;
	  break;

	case SSTP_MSG_ECHO_REQUEST:
	  /* a implementer */
	  break;
	  
	case SSTP_MSG_ECHO_REPLY:
	  if (ctx->state != CLIENT_CALL_CONNECTED) return -1;
	  alarm(0);

	  break;
	  
	  /*
	   * Client SHOULD NEVER receive teh following message.
	   * If so, close (dirtiliy) the client.
	   */
	case SSTP_MSG_CALL_CONNECT_REQUEST:
	case SSTP_MSG_CALL_DISCONNECT_ACK:
	default :
	  xlog(LOG_ERROR, "Client cannot handle type %#x\n", control_type);
	  ctx->state = CLIENT_CALL_DISCONNECTED;
	  return -1;
	}
      
    }
  else 
    {
      void* data_ptr;
      data_ptr = rbuffer + sizeof(sstp_header_t);
      
      /* if PPP-CHAP is successful*/
      if ( ntohs(*((uint16_t*)data_ptr)) == 0xc223 &&
	   (*(uint8_t*)(data_ptr + 2)) == 0x03 )
	{
	  size_t attribute_len;
	  void* attribute;
	  sstp_attribute_crypto_bind_t crypto_settings;

	  memset(&crypto_settings, 0, sizeof(sstp_attribute_crypto_bind_t));

	  /* send SSTP_MSG_CALL_CONNECTED */
	  attribute_len = sizeof(sstp_attribute_header_t) + sizeof(sstp_attribute_crypto_bind_t);
	  crypto_settings.hash_bitmask = ctx->hash_algorithm;
	  memcpy(crypto_settings.nonce, ctx->nonce, sizeof(uint32_t)*8);
	  memcpy(crypto_settings.certhash, ctx->certhash, sizeof(uint32_t)*8);
	  memcpy(crypto_settings.cmac, ctx->cmac, sizeof(uint32_t)*8);
	  
	  attribute = create_attribute(SSTP_ATTRIB_CRYPTO_BINDING, &crypto_settings,
				       sizeof(sstp_attribute_crypto_bind_t));
	  
	  send_sstp_control_packet(SSTP_MSG_CALL_CONNECTED, attribute, 1, attribute_len);

	  free(attribute);

	  /* and set hello timer */
	  alarm(ctx->hello_timer.tv_sec);
	  change_status(CLIENT_CALL_CONNECTED);
	  
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
      sstp_attribute_header_t* attribute_header;
      void* attribute_data;
      uint8_t attribute_id;
      uint16_t attribute_length;
      
      attribute_header = (sstp_attribute_header_t*) attr_ptr;
      attribute_id = attribute_header->attribute_id;
      attribute_length = ntohs( attribute_header->packet_length );
      attribute_data = (attr_ptr + sizeof(sstp_attribute_header_t));


      /* checking attribute header*/
      bytes_to_read -= attribute_length;
      if (bytes_to_read < 0) 
	{
	  xlog(LOG_ERROR, "Trying to read at incorrect offset in control packet.\n");
	  return -1;
	}
      if (attribute_id > SSTP_ATTRIB_CRYPTO_BINDING_REQ)
	{
	  xlog(LOG_ERROR, "Incorrect attribute id.\n");
	  return -1;
	}
      
      /* parsing attribute header */
      if (cfg->verbose)
	{
	  xlog(LOG_INFO, "\t\t--> attribute_id:%s (%#.2x)\n",attr_types_str[attribute_id], attribute_id);
	  xlog(LOG_INFO, "\t\t--> len: %d bytes\n", attribute_length);
	}

      switch (attribute_id)
	{
	case SSTP_ATTRIB_NO_ERROR: break;

	case SSTP_ATTRIB_STATUS_INFO:
	  retcode = attribute_status_info(attribute_data, attribute_length);
	  break;
	  
	case SSTP_ATTRIB_CRYPTO_BINDING_REQ:	  
	  retcode = crypto_set_binding(attribute_data);
	  break;

	  /* cas a ne pas traiter */
	case SSTP_ATTRIB_CRYPTO_BINDING:
	case SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID:
	default:
	  xlog(LOG_ERROR, "Attribute ID %#x is not handled on client side.\n", attribute_id);
	  retcode = -1;
	}

      if (retcode < 0) break;
            
      attr_ptr += attribute_length;
      attrnum--;
    }
  
  return retcode;
}


void sstp_send(void* data, size_t data_length)
{
  ssize_t sbytes;

  sbytes = gnutls_record_send(tls, data, data_length);
  
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


void send_sstp_data_packet(void* data, size_t len) 
{
  send_sstp_packet(SSTP_DATA_PACKET, data, len);
}


void send_sstp_control_packet(uint16_t msg_type, void* attributes,
			      uint16_t attribute_number, size_t attributes_len)
{
  sstp_control_header_t control_header;
  size_t control_length;
  void *data, *data_ptr, *attr_ptr;

  if (attributes == NULL && attribute_number != 0)
    {
      xlog(LOG_ERROR, "No attribute specified. Cannot send message.\n");
      return;
    } 
  
  control_length = sizeof(sstp_control_header_t) + attributes_len; 
  memset(&control_header, 0, sizeof(sstp_control_header_t));

  /* setting control header */
  control_header.message_type = htons(msg_type);
  control_header.num_attributes = htons(attribute_number);

  /* filling control with attributes */
  data = xmalloc(control_length);
  memcpy(data, &control_header, sizeof(sstp_control_header_t));

  attr_ptr = attributes;
  data_ptr = data + sizeof(sstp_control_header_t);
  
  while (attribute_number)
    {
      sstp_attribute_header_t* cur_attr = (sstp_attribute_header_t*)attr_ptr;
      uint16_t plen = ntohs(cur_attr->packet_length);
      
      memcpy(data_ptr, attr_ptr, plen);
      attr_ptr += plen;
      data_ptr += plen;
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
	{
	  xlog(LOG_ERROR, "Current state: %#x. Expected %#x\n",
	       ctx->state, CLIENT_CONNECT_REQUEST_SENT);
	}
      
      return -1;
    }
  
  /* setting crypto properties */
  req = (sstp_attribute_crypto_bind_req_t*) data;
  hash = req->hash_bitmask;
  
  if ( hash!=CERT_HASH_PROTOCOL_SHA1 && hash!=CERT_HASH_PROTOCOL_SHA256)
    {
      xlog(LOG_ERROR, "Unknown hash algorithm %#x\n", hash);
      return -1;
    }

  /* choose strongest algorithm */
  if (hash == CERT_HASH_PROTOCOL_SHA256)
    ctx->hash_algorithm = CERT_HASH_PROTOCOL_SHA256;
  else
    ctx->hash_algorithm = CERT_HASH_PROTOCOL_SHA1;

  memcpy(ctx->nonce, req->nonce, sizeof(uint32_t)*8);
  
  if (cfg->verbose)
    {
      xlog(LOG_INFO, "\t\t--> hash algo: %s (%#.2x)\n", crypto_req_attrs_str[ctx->hash_algorithm],
	   ctx->hash_algorithm);
      xlog(LOG_INFO, "\t\t--> nonce: 0x");
      for (i=0; i<8; i++) xlog(LOG_INFO, "%x", ctx->nonce[i]);
      xlog(LOG_INFO, "\n");
    }
  
  /* compute ca file hash with chosen algorithm */
  if (crypto_set_certhash() < 0)
    return -1;

  /* compute compound mac according to spec */
  if (crypto_set_cmac() < 0)
    return -1;
  
  /* change client state */
  change_status(CLIENT_CONNECT_ACK_RECEIVED);

  return 0;
}


int crypto_set_certhash()
{
  int val,i;
  unsigned char dst[32];
  size_t buffer_len = 4096; 
  char buffer[buffer_len];
  unsigned char* (*HASH)();
  
  memset(buffer, 0, buffer_len);
  
  /* export certificate to DER format */
  val = gnutls_x509_crt_export (certificate, GNUTLS_X509_FMT_DER, buffer, &buffer_len);
  if (val != GNUTLS_E_SUCCESS) 
    {
      xlog(LOG_ERROR, "crypto_set_certhash: fail to export certificate\n");
      if (val == GNUTLS_E_SHORT_MEMORY_BUFFER)
	xlog(LOG_ERROR, "Missing memory (expected %d)\n", buffer_len);
      return -1;
    }

  /* select hash algorithm */
  if (ctx->hash_algorithm == CERT_HASH_PROTOCOL_SHA256)
    {
      val = SHA256_MAC_LEN;
      HASH = &SHA256;
    }
  else 
    {
      val = SHA1_MAC_LEN;
      HASH = &SHA1;
    }

  /* compute hash  */
  HASH(buffer, buffer_len, dst);
  
  /* move hash to client context variable */
  memcpy(ctx->certhash, dst, 8 * sizeof(uint32_t));
  
  if (cfg->verbose)
    {
      xlog(LOG_INFO, "\t\t--> CA hash: 0x");
      for(i=0; i<8; i++) xlog(LOG_INFO, "%x", ctx->certhash[i]);
      xlog(LOG_INFO, "\n");
    }
  
  return 0;
}


int crypto_set_cmac()
{ 
  uint8_t hlak[32];
  int i;
  uint8_t *cmac;
  uint8_t seed[SSTP_CMAC_SEED_LEN];
  
  /*
   * `If the higher-layer PPP authentication method did not generate any keys, or if PPP authentication
   * is bypassed (i.e. ClientBypassHLAuth is set to TRUE), then the HLAK MUST be 32 octets of
   * 0x00.`
   * Ok, that what will do. HLAK is zero-ed.
   */
  memset(hlak, 0, 32 * sizeof(uint8_t));
  memcpy(seed, SSTP_CMAC_SEED_STR, SSTP_CMAC_SEED_LEN);
  
  if (ctx->hash_algorithm == CERT_HASH_PROTOCOL_SHA1)
    cmac = PRF(hlak, seed, SHA1_MAC_LEN);
  else
    cmac = PRF(hlak, seed, SHA256_MAC_LEN);
 
  for (i=0;i<8;i++)
    ctx->cmac[i] = htonl(*(uint32_t*)(cmac+(i*4)));
  free(cmac);
  
  if (cfg->verbose)
    {
      xlog(LOG_INFO, "\t\t--> CMac: 0x");
      for(i=0;i<8;i++) xlog(LOG_INFO, "%x", ctx->cmac[i]);
      xlog(LOG_INFO, "\n");
    }
  
  return 0;
}


int attribute_status_info(void* data, uint16_t attr_len)
{
  sstp_attribute_status_info_t* info;
  uint8_t attribute_id;
  uint32_t status;
  int rbytes;

  info = (sstp_attribute_status_info_t*) data;
  attribute_id = info->attrib_id;
  status = ntohl(info->status);

  /* check attribute */
  if (attribute_id > ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG)
    {
      xlog(LOG_ERROR, "Attribute id is not valid.\n");
      return -1;
    }

  /* show attribute */
  xlog(LOG_INFO, "\t\t--> attribute ref: %s (%#.2x)\n", attr_types_str[attribute_id], attribute_id);
  xlog(LOG_INFO, "\t\t--> status: %s (%#.2x)\n", attrib_status_str[status], status);

  if (ctx->state != CLIENT_CONNECT_REQUEST_SENT) return 0;
  
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


/**
 * Adapted from ssl_ppp_fork() in /ssltunnel-1.18/client/main.c
 * At http://www.hsc.fr/ressources/outils/ssltunnel/download/ssltunnel-1.18.tar.gz
 * Alain Thivillon et Herve Schauer Consultants
 *
 * \brief fork and execute pppd daemon
 * \retval child pid if process is the father
 * \retval none otherwise (execute pppd)
 **/
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
  pppd_args[i++] = "noauth";
  pppd_args[i++] = "nodefaultroute";
  pppd_args[i++] = "9600"; 
  pppd_args[i++] = "sync";
  pppd_args[i++] = "refuse-eap";
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

  return 0;
}


/**
 * from : http://open1x.svn.sourceforge.net/svnroot/open1x/trunk/xsupplicant/src/eap_types/peap/peap_extensions.c
 * \brief PRF+ as defined by the Microsoft PEAP documentation.
 *
 * @param[in] key   The "TempKey" as defined by the Microsoft PEAP documentation
 *                                      (The first 40 octets of the TK)
 * @param[in] seed   The IPMK Seed.
 * @param[in] len   The minimum amount of result data we need to provide.
 *
 * \retval NULL on failure
 * \retval uint8_t* containing at least 'len' bytes
 **/

uint8_t * PRF(uint8_t * key, uint8_t * seed, uint8_t len)
{
  uint8_t iterations = 0;
  int i = 0;
  uint8_t *temp_data = NULL;
  uint8_t last_val[20];
  uint8_t *Tn = NULL;
  uint8_t mac[20];
  unsigned int mdlen = 0;
  
  const EVP_MD* (*HASH)();

  if (len == SHA1_MAC_LEN)
    HASH = &EVP_sha1;
  else
    HASH = &EVP_sha256; 
  
  iterations = (len / 32);

  if ((len % 32) != 0)
    iterations++;   // We need a fractional amount of data, so round up.

  Tn = (uint8_t*)xmalloc(iterations * 32);
  temp_data = (uint8_t*) xmalloc(SSTP_CMAC_SEED_LEN + 3);
  memcpy(temp_data, seed, SSTP_CMAC_SEED_LEN);

  temp_data[SSTP_CMAC_SEED_LEN] = 0x01;
  
  // Malloc should have inited everything else to 0x00, so we don't need to set those.
  HMAC(HASH(),
       key, 32,
       temp_data, (SSTP_CMAC_SEED_LEN + 3),
       (unsigned char *)&mac, &mdlen);

  if (mdlen != len)
    {
      xlog(LOG_INFO, "The SHA1 hash function didn't return valid data!\n");
      free(temp_data);
      free(Tn);

      return NULL;
    }

  /* xlog(LOG_DEBUG, "Hash result : %d bytes\n", mdlen); */

  memcpy(Tn, &mac[0], mdlen);     // Copy the initial data to Tn.
  memcpy(&last_val[0], &mac[0], mdlen);

  free(temp_data);

  if (iterations >= 2)
    {
      for (i = 2; i <= iterations; i++)
	{
	  temp_data = (uint8_t*) xmalloc(SHA256_MAC_LEN + SSTP_CMAC_SEED_LEN + 3);
	  
	  memcpy(temp_data, last_val, SHA256_MAC_LEN);
	  memcpy(&temp_data[SHA256_MAC_LEN], seed, SSTP_CMAC_SEED_LEN);

	  temp_data[SHA256_MAC_LEN + SSTP_CMAC_SEED_LEN] = i;

	  // Malloc should have inited everything else to 0x00, so we don't need to set those.
	  HMAC(EVP_sha1(), key, 40, temp_data,
	       (SHA256_MAC_LEN + SSTP_CMAC_SEED_LEN + 3),
	       (unsigned char *)&mac, &mdlen);
	  
	  if (mdlen != SHA256_MAC_LEN)
	    {
	      xlog(LOG_DEBUG, "SHA1 hash didn't return valid data in %s()!\n", __FUNCTION__);
	      free(temp_data);
	      free(Tn);
	      return NULL;
	    }
	  
	  free(temp_data);

	  /* xlog(LOG_DEBUG, "Hash result %d bytes\n", mdlen); */
	  
	  memcpy(&last_val[0], &mac[0], SHA256_MAC_LEN);
	  memcpy(&Tn[((i - 1) * SHA256_MAC_LEN)], &mac[0], SHA256_MAC_LEN);
	}
    }
  
  return Tn;
}
