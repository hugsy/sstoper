/*
 * SSToPer, Linux SSTP Client
 * Christophe Alladoum < christophe __DOT__ alladoum __AT__ hsc __DOT__ fr>
 * Herve Schauer Consultants (http://www.hsc.fr)
 *
 *            GNU GENERAL PUBLIC LICENSE
 *              Version 2, June 1991
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (
 * at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define _GNU_SOURCE 1
#define _POSIX_SOURCE 1


#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/hmac.h>
#include <openssl/md4.h>

#ifdef HAS_GNUTLS
#include <gnutls/x509.h>
#include <gnutls/gnutls.h>
#else
#include <polarssl/net.h>
#include <polarssl/debug.h>
#include <polarssl/ssl.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/error.h>
#include <polarssl/certs.h>

#include "pem2der.h"
#endif

#include "libsstp.h"
#include "main.h"

#if defined __linux__
#include <pty.h>
#endif


/**
 * SSTP I/O primitive for reading
 *
 * @param buf : buffer to read
 * @param buflen : number of bytes to read
 * @return size read if >0 or error if <0
 */
static ssize_t sstp_read(unsigned char *buf, size_t buflen)
{
        ssize_t rbytes;

#ifdef HAS_GNUTLS
        rbytes = gnutls_record_recv(tls, buf, buflen);
        if (rbytes < 0)
                xlog(LOG_ERROR, "sstp_read: %s\n", gnutls_strerror(rbytes));

#else
        int do_loop = 1;

        char msg[512] = {0,};
        do {
                rbytes = ssl_read(&tls, buf, buflen);
                if (rbytes < 0)
                {
                        error_strerror(rbytes, msg, sizeof(msg)-1);
                        xlog(LOG_ERROR, "sstp_read() failed: %d - %s\n", rbytes, msg);
                        return -1;
                }

                switch(rbytes)
                {
                        case POLARSSL_ERR_NET_WANT_READ:
                        case POLARSSL_ERR_NET_WANT_WRITE:
                                continue;

                        case POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY:
                        case 0:
                                do_loop = 0;
                                break;

                        default:
                              do_loop = 0;
                              break;
                }

        } while( do_loop );
#endif

  if (cfg->verbose)
          xlog(LOG_INFO, " <-- %lu bytes\n", rbytes);

  return rbytes;
}


/**
 * SSTP I/O primitive for writing
 *
 * @param buf : buffer to write
 * @param buflen : number of bytes to write
 * @return size written if >0 or error if <0
 */
static ssize_t sstp_write(unsigned char *buf, size_t buflen)
{
  ssize_t sbytes;

#ifdef HAS_GNUTLS
  sbytes = gnutls_record_send(tls, buf, buflen);
  if (sbytes < 0){
          xlog(LOG_ERROR, "sstp_write: %s\n", gnutls_strerror(sbytes));
          return -1;
  }

#else
  char msg[512] = {0,};

  sbytes = ssl_write(&tls, buf, buflen);
  if (sbytes < 0)
  {
          if(sbytes != POLARSSL_ERR_NET_WANT_READ && sbytes != POLARSSL_ERR_NET_WANT_WRITE )
          {
                  error_strerror(sbytes, msg, sizeof(msg)-1);
                  xlog(LOG_ERROR, "sstp_write() failed: %x: %s\n", sbytes, msg);
                  return -1;
          }
  }

#endif

  if (cfg->verbose)
          xlog(LOG_INFO, " --> %lu bytes\n", sbytes);

  return sbytes;
}


/**
 * Encapsulated data provided as argument inside a SSTP packet. SSTP packet type
 * (control|data) should be specified throught `type` argument.
 *
 * @param type : set packet type (Control or Data)
 * @param data : buffer to be sent
 * @param data_length : `data` length
 */
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

  sstp_write(packet, total_length);

  xfree(packet);
}


/**
 * Generic function to send an SSTP Data packet. Data to send is encapsulated
 * inside an SSTP packet, and transmitted througth TLS session.
 * As this function intercepts PPP packets, it is also used to detect PPP
 * negociation success, and stores NT Response code inside client chap_ctx.
 *
 * @param data : buffer to be sent
 * @param len : `data` length
 */
void send_sstp_data_packet(void* data, size_t len)
{
  if ( ntohs(*((uint16_t*)data)) == 0xc223 )
    {
      uint8_t chap_handshake_code = *(uint8_t*)(data + 2);

      /* if msg is PPP-CHAP response */
      if (chap_handshake_code == 0x02 )
	{
	  memcpy(chap_ctx, data+7, 49);
	}
    }

  send_sstp_packet(SSTP_DATA_PACKET, data, len);
}



/**
 * Generic function to send an SSTP control packet. As a control packet embeds one
 * or many attributes, they also should be specified.
 *
 * @param msg_type : SSTP control message type
 * @param attributes : pointer to the attributes buffer
 * @param attribute_number : number of attributes inside buffer
 * @param attributes_len : `attributes` length
 */
void send_sstp_control_packet(uint16_t msg_type, void* attributes,
			      uint16_t attribute_number, size_t attributes_len)
{
  sstp_control_header_t control_header;
  size_t control_length;
  uint16_t i;
  void *data, *data_ptr, *attr_ptr;

  if (!attributes && attribute_number)
    {
      xlog(LOG_ERROR, "No attribute specified. Cannot send message.\n");
      return;
    }

  control_length = sizeof(sstp_control_header_t) + attributes_len;
  memset(&control_header, 0, sizeof(sstp_control_header_t));

  /* setting control header */
  control_header.message_type = htons(msg_type);
  control_header.num_attributes = htons(attribute_number);

  if (cfg->verbose > 2)
    {
      xlog(LOG_DEBUG, "\t-> Control packet\n");
      xlog(LOG_DEBUG, "\t-> type: %s (%#.2x)\n",
	   control_messages_types_str[msg_type], msg_type);
      xlog(LOG_DEBUG, "\t-> attribute number: %d\n", attribute_number);
      xlog(LOG_DEBUG, "\t-> length: %d\n", control_length);
    }


  /* filling control with attributes */
  data = xmalloc(control_length);
  memcpy(data, &control_header, sizeof(sstp_control_header_t));

  attr_ptr = attributes;
  data_ptr = data + sizeof(sstp_control_header_t);

  for (i=0; i<attribute_number; i++)
    {
      sstp_attribute_header_t* cur_attr = (sstp_attribute_header_t*)attr_ptr;
      uint16_t plen = ntohs(cur_attr->packet_length);

      if (cfg->verbose > 2)
	{
	  xlog(LOG_DEBUG, "\t\t--> Attribute %d\n", i);
	  xlog(LOG_DEBUG, "\t\t--> type: %s (%x)\n",
	       attr_types_str[cur_attr->attribute_id], cur_attr->attribute_id);
	  xlog(LOG_DEBUG, "\t\t--> length: %d\n", plen);
	}

      memcpy(data_ptr, attr_ptr, plen);
      attr_ptr += plen;
      data_ptr += plen;
    }


  /* yield to lower */
  send_sstp_packet(SSTP_CONTROL_PACKET, data, control_length);

  xfree(data);
}


/**
 * Generate an GUID identifier for the SSTP connection
 *
 * @param data : buffer to store guid
 */
static void generate_guid(char data[])
{
  uint32_t data1, data4;
  uint16_t data2, data3;
  struct timeval tv;
  unsigned int seed;

  gettimeofday(&tv, NULL);
  seed = tv.tv_usec * tv.tv_sec;
  seed ^= getpid();

  memset(data, 0, 39);
  srand (seed);
  data1 = (rand() + 1) * (sizeof(uint32_t) * 8);
  data2 = (rand() + 1) * (sizeof(uint16_t) * 8);
  data3 = (rand() + 1) * (sizeof(uint16_t) * 8);
  data4 = (rand() + 1) * (sizeof(uint32_t) * 8);
  snprintf(data, 38, "{%.4X-%.2X-%.2X-%.4X}", data1, data2, data3, data4);

  if (cfg->verbose > 2)
    xlog(LOG_DEBUG, "Using GUID %s\n", data);
}


/**
 * Change client state
 *
 * @param status : new status
 */
void set_client_status(uint8_t status)
{
  if (ctx->state == status)
    return;

  if (cfg->verbose)
    xlog(LOG_INFO, "status: %s (%#x) -> %s (%#x)\n",
	 client_status_str[ctx->state], ctx->state,
	 client_status_str[status], status);

  ctx->state = status;
}


/**
 * Header validation.
 *
 * @param header : sstp header to analyse
 * @param recv_len : number of bytes received
 * @return TRUE if valid, FALSE otherwise
 */
static int is_valid_header(sstp_header_t* header, ssize_t recv_len)
{

  if (header->version != SSTP_VERSION)
    {
      if (cfg->verbose)
	xlog(LOG_ERROR, "Invalid version (%#x)\n", header->version);
      return FALSE;
    }

  if (header->reserved != SSTP_DATA_PACKET &&
      header->reserved != SSTP_CONTROL_PACKET)
    {
      if (cfg->verbose)
	xlog(LOG_ERROR, "Invalid packet type (%#x)\n", header->reserved);
      return FALSE;
    }

  header->length = ntohs(header->length);
  if (header->length > recv_len)
    {
      if ( header->reserved == SSTP_CONTROL_PACKET)
	{
	  if (cfg->verbose > 2)
	    xlog(LOG_DEBUG, "Unmatching length: annonced %lu, received %lu\n",
		 header->length, recv_len);

	  return FALSE;
	}
    }

  return TRUE;
}


/**
 * Check whether received packet has Control flag raised.
 *
 * @param packet_header : received SSTP header
 * @return TRUE if valid, FALSE otherwise
 */
static int is_control_packet(sstp_header_t* packet_header)
{
  return (packet_header->reserved == SSTP_CONTROL_PACKET);
}


/**
 * Send HTTP request to start a new SSTP connection.
 *
 * @return 0 if all good, negative value otherwise
 */
int https_session_negociation()
{
  ssize_t rbytes;
  unsigned char buf[1024] = {0, };
  char guid[39] = {0, };

  rbytes = -1;

  /* Allocate SSTP session */
  sess = (sstp_session_t*) xmalloc(sizeof(sstp_session_t));

  generate_guid(guid);
  rbytes = snprintf((char *)buf, 1024,
		    "SSTP_DUPLEX_POST %s HTTP/1.1\r\n"
		    "Host: %s\r\n"
		    "SSTPCORRELATIONID: %s\r\n"
		    "Content-Length: %llu\r\n"
		    "\r\n",
		    SSTP_HTTPS_RESOURCE,
		    cfg->server,
		    guid,
  		    __UNSIGNED_LONG_LONG_MAX__);

  if (cfg->verbose > 2)
    xlog(LOG_DEBUG, "Sending: %lu bytes\n%s\n", rbytes, buf);

  /* Start negociation */
  if (sstp_write(buf, rbytes) < 0)
  {
          xlog(LOG_ERROR, "%s", "Failed to send the SSTP_DUPLEX_POST request\n");
          return -1;
  }

  memset(buf, 0, 1024);
  rbytes = sstp_read(buf, 1024);
  if (rbytes < 0)
  {
          xlog(LOG_ERROR, "%s", "Failed to receive the SSTP_DUPLEX_POST response\n");
          return -1;
  }

  if (rbytes == 0)
  {
          xlog(LOG_INFO, "Unexpected close notification from %s.\n", cfg->server);
          return -1;
  }

  if (cfg->verbose)
  {
          if (cfg->verbose > 1)
                  xlog(LOG_DEBUG , "Received: %s\n", buf);
  }

  sess->rx_bytes += rbytes;
  if (cfg->verbose > 2)
          xlog(LOG_DEBUG, "Received: %lu bytes\n%s\n", rbytes, buf);

  if (memcmp(buf, "HTTP/1.1 200", 12) && memcmp(buf, "HTTP/1.0 200", 12))
    {
      xlog(LOG_ERROR, "Incorrect HTTP response header\n");
      if (cfg->verbose > 2)
	{
	  buf[sizeof(buf)-1] = '\0';
	  xlog(LOG_DEBUG, "%s\n", buf);
	}

      return -1;
    }

  return 0;
}


/**
 * Allocates and fills an attribute with specified data.
 *
 * @param attribute_id : attribute code
 * @param data : data to be inserted
 * @param data_length : `data` length
 * @return a pointer to the new attribute buffer
 */
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


/**
 * Emits SSTP negociation request, ie Control message with
 * ENCAPSULATED_PROTOCOL_ID attribute. Negociation timer is set up and state is
 * changed.
 */
static void sstp_init()
{
  uint16_t attribute_data;
  void* attribute;
  size_t attribute_len;

  attribute_data = htons(SSTP_ENCAPSULATED_PROTOCOL_PPP);
  attribute_len = sizeof(sstp_attribute_header_t) + sizeof(uint16_t);
  attribute = create_attribute(SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID,
			       (void*)&attribute_data, sizeof(uint16_t));

  send_sstp_control_packet(SSTP_MSG_CALL_CONNECT_REQUEST, attribute,
			   1, attribute_len);

  xfree(attribute);

  alarm(ctx->negociation_timer.tv_sec);
  ctx->flags |= NEGOCIATION_TIMER_RAISED;

  set_client_status(CLIENT_CONNECT_REQUEST_SENT);

}


/**
 * Print attribute information.
 *
 * @param data
 * @param attr_len
 */
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

  if (cfg->verbose > 2)
    {
      /* show attribute */
      xlog(LOG_DEBUG, "\t\t--> attr_ref\t%s (%#.2x)\n", attr_types_str[attribute_id], attribute_id);
      xlog(LOG_DEBUG, "\t\t--> status\t%s (%#.2x)\n", attrib_status_str[status], status);
    }

  if (ctx->state != CLIENT_CONNECT_REQUEST_SENT)
    return 0;

  /* attrib_value is at most 64 bytes (ie full attr len <= 64 + 12 bytes) */
  rbytes = sizeof(sstp_attribute_header_t) + 2*sizeof(uint32_t);

  while (rbytes < (64+12) && rbytes < attr_len)
    {
      uint32_t attrib_value;
      attrib_value = ntohl(*((uint32_t*)data + rbytes));
      if (cfg->verbose > 2)
	xlog(LOG_DEBUG, "\t\t--> attribute value: %#.4x\n", attrib_value);
      rbytes += sizeof(uint32_t);
    }

  return 0;
}


/**
 * The main loop will be called right after the end of HTTPS negociation and
 * - allocates SSTP client context regions
 * - start an SSTP negociation
 * - handle receive packets
 * - send packets
 */
void sstp_loop(pid_t pppd_pid)
{
  fd_set rcv_fd;
  int retcode;
  uint16_t msg_type = 0;

  gettimeofday(&sess->tv_start, NULL);

  ctx = (sstp_context_t*) xmalloc(sizeof(sstp_context_t));
  ctx->retry                       = SSTP_MAX_INIT_RETRY;
  ctx->state                       = CLIENT_CALL_DISCONNECTED;
  ctx->negociation_timer.tv_sec    = SSTP_NEGOCIATION_TIMER;
  ctx->hello_timer.tv_sec          = SSTP_NEGOCIATION_TIMER;
  ctx->pppd_pid                    = pppd_pid;

  chap_ctx = (chap_context_t*) xmalloc(sizeof(chap_context_t));


  /* start negociation */
  sstp_init();


  while(ctx->state != CLIENT_CALL_DISCONNECTED)
    {
      FD_ZERO(&rcv_fd);

      if (ctx->pppd_pid > 0)
	FD_SET(0, &rcv_fd);

      FD_SET(sockfd, &rcv_fd);

      retcode = select(sockfd + 1, &rcv_fd, NULL, NULL, NULL);
      if ( retcode < 0 )
	{
	  xlog(LOG_ERROR, "sstp_loop: %s\n", strerror(errno));
	  set_client_status(CLIENT_CALL_DISCONNECTED);
	  break;
	}

      if (ctx->pppd_pid > 0 && FD_ISSET(0, &rcv_fd))
	{
	  unsigned char rbuffer[PPP_MAX_MRU];
	  ssize_t rbytes = -1;
	  memset(rbuffer, 0 , PPP_MAX_MRU);

	  rbytes = read(0, rbuffer, PPP_MAX_MRU);
	  if (rbytes > 0)
	    send_sstp_data_packet(rbuffer, rbytes);
	}

      if (FD_ISSET(sockfd, &rcv_fd))
	{
	  unsigned char rbuffer[PPP_MAX_MRU];
	  ssize_t rbytes;
	  memset(rbuffer, 0 , PPP_MAX_MRU);

	  rbytes = sstp_read(rbuffer, PPP_MAX_MRU);
	  if (rbytes < 0)
	      retcode = rbytes;

	  else if (rbytes == 0)
	    {
	      if (cfg->verbose)
		xlog(LOG_INFO, "sstp_loop: EOF\n");
	    }

	  else
	    {
	      if (cfg->verbose)
		xlog(LOG_INFO,"<--  %lu bytes\n", rbytes);

	      sess->rx_bytes += rbytes;
	      retcode = sstp_decode(rbuffer, rbytes);
	    }

	  if (retcode < 0)
	    break;
	}
    }

  if (ctx->pppd_pid > 0)
    {
      if (cfg->verbose)
	xlog(LOG_INFO, "Waiting for %s process (PID:%d) to end\n",
	     cfg->pppd_path, ctx->pppd_pid);

      kill(ctx->pppd_pid, SIGINT);
      waitpid(ctx->pppd_pid, &retcode, 0);

      if (retcode)
	xlog(LOG_ERROR, "Failed to quit pppd, retcode %d\n", retcode);
    }

  msg_type = ctx->flags & REMOTE_DISCONNECTION ? SSTP_MSG_CALL_DISCONNECT_ACK : SSTP_MSG_CALL_DISCONNECT;

  if (cfg->verbose)
    xlog(LOG_INFO, "Sending %s message.\n", control_messages_types_str[msg_type]);
  send_sstp_control_packet(msg_type, NULL, 0, 0);

  gettimeofday(&sess->tv_end, NULL);

  if (cfg->verbose)
    {
      unsigned int session_time = sess->tv_end.tv_sec - sess->tv_start.tv_sec;

      xlog(LOG_INFO, "SSTP session duration: %lu sec\n", session_time);
      xlog(LOG_INFO, "Sent %lu bytes (avg: %.2f B/s), received %lu bytes (avg: %.2f B/s)\n",
	   sess->rx_bytes,
	   (float)(sess->rx_bytes/session_time),
	   sess->tx_bytes,
	   (float)(sess->tx_bytes/session_time)
	   );
    }

  xfree(chap_ctx);
  xfree(sess);
  xfree(ctx);
}


/**
 * This function is called by crypto_set_binding() and computes server certificate
 * hash. Since certificate is provided as PEM format, it is first exported to DER
 * binary format, hashed with context-defined algorithm, and stored inside client
 * SSTP context.
 *
 * @return 0 if all good, negative value otherwise
 */
int crypto_set_certhash()
{
  int val,i;
  unsigned char dst[32] = {0, };
  unsigned char* (*HASH)();


  /* export certificate to DER format */
#ifdef HAS_GNUTLS
  unsigned char buffer[8192] = {0, };
  size_t buffer_len = sizeof(buffer);

  val = gnutls_x509_crt_export (certificate, GNUTLS_X509_FMT_DER, buffer, &buffer_len);
  if (val != GNUTLS_E_SUCCESS)
    {
      xlog(LOG_ERROR, "crypto_set_certhash: fail to export certificate\n");
      if (val == GNUTLS_E_SHORT_MEMORY_BUFFER)
	xlog(LOG_ERROR, "Missing memory (expected %d)\n", buffer_len);
      return -1;
    }
#else
  unsigned char *ibuf;

  unsigned char obuf[8192] = {0, };
  size_t ibuflen, obuflen;

  if(cfg->verbose > 1)
          xlog(LOG_DEBUG, "[polarssl] converting '%s' PEM -> DER format\n", cfg->ca_file);

  if (load_file(cfg->ca_file, (unsigned char **)&ibuf, &ibuflen) < 0)
  {
          xlog(LOG_ERROR, "Failed to load '%s': %d - %s\n", cfg->ca_file, errno, strerror(errno));
          return -1;
  }

  if (convert_pem_to_der(ibuf, ibuflen, obuf, &obuflen) < 0)
  {
          xlog(LOG_ERROR, "Failed to convert '%s' to DER\n", cfg->ca_file);
          xfree(ibuf);
          return -1;
  }

  xfree(ibuf);

  if(cfg->verbose > 2)
          xlog(LOG_DEBUG, "Converted '%s' PEM=%d bytes -> DER=%d bytes\n", cfg->ca_file, ibuflen, obuflen);

#endif

  /* select hash algorithm */
  if (ctx->hash_algorithm == CERT_HASH_PROTOCOL_SHA256)
    {
      val = SHA256_HASH_LEN;
      HASH = &SHA256;
    }
  else
    {
      val = SHA1_HASH_LEN;
      HASH = &SHA1;
    }

  /* compute hash  */
#ifdef HAS_GNUTLS
  HASH(buffer, buffer_len, dst);
#else
  HASH(obuf, obuflen, dst);
#endif

  /* move hash to client context variable */
  for(i=0; i<8; i++) ctx->certhash[i] = *(uint32_t*)(dst+(i*4));

  return 0;
}


/**
 * On receiving a binding request, this function is triggered to prepare
 * cryptographic properties. It selects strongest negociated hash algorithm,
 * stores Nonce into client SSTP context, invoke certhash(), and changes client
 * state.
 *
 * @param data : pointer to crypto binding request packet
 * @return 0 if all good, negative value otherwise
 */
int crypto_set_binding(void* data)
{
  sstp_attribute_crypto_bind_req_t* req;

  /* Validating client state */
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

  /* Disable negociation timer */
  alarm(0);
  ctx->flags &= ~NEGOCIATION_TIMER_RAISED;

  /* Setting crypto properties */
  req = (sstp_attribute_crypto_bind_req_t*) data;

  /* Setting hash algorithm type (SHA1 or SHA256) */
  switch(req->hash_bitmask)
    {
    case CERT_HASH_PROTOCOL_SHA256:
      ctx->hash_algorithm = CERT_HASH_PROTOCOL_SHA256;
      break;

    case CERT_HASH_PROTOCOL_SHA1:
      ctx->hash_algorithm = CERT_HASH_PROTOCOL_SHA1;
      break;

    default:
      xlog(LOG_ERROR, "Unknown hash algorithm %#x\n", req->hash_bitmask);
      return -1;
    }

  memcpy(ctx->nonce, req->nonce, sizeof(uint32_t) * 8);

  /* compute ca file hash with chosen algorithm */
  if (crypto_set_certhash() < 0)
    return -1;

  /* change client state */
  set_client_status(CLIENT_CONNECT_ACK_RECEIVED);

  return 0;
}



/**
 * Defines Compound Mac value and store its value into SSTP client context.
 *
 * @return 0 on SUCCESS, < 0 on ERROR
 */
int crypto_set_cmac()
{
  uint16_t hash_len;
  unsigned char Call_Connected_buffer[112];

  uint8_t hlak[32];
  uint8_t *cmac, *cmk;
  uint8_t msg[32];
  uint8_t PasswordHash[MD4_DIGEST_LENGTH];
  uint8_t PasswordHashHash[MD4_DIGEST_LENGTH];
  uint8_t NT_Response[24];
  uint8_t Master_Key[16];
  uint8_t Master_Send_Key[16];
  uint8_t Master_Receive_Key[16];

  uint8_t* ptr = NULL;

  unsigned char Call_Connected_header[16] =
    {
      0x10, 0x01, 0x00, 0x70, 0x00, 0x04, 0x00, 0x01,
      0x00, 0x03, 0x00, 0x68, 0x00, 0x00, 0x00, 0x02
    };

  memset(hlak, 0, 32);
  memset(PasswordHash, 0, MD4_DIGEST_LENGTH);
  memset(PasswordHashHash, 0, MD4_DIGEST_LENGTH);
  memset(NT_Response, 0, 24);
  memset(Call_Connected_buffer, 0, 112);


  /* Crypto super fun time */

  /* Setting HLAK */
  NtPasswordHash( PasswordHash, (const uint8_t *)cfg->password, strlen(cfg->password) );
  HashNtPasswordHash( PasswordHashHash, PasswordHash );
  memcpy( NT_Response, chap_ctx->response_nt_response, 24 );
  GetMasterKey( Master_Key, PasswordHashHash, NT_Response );
  GetAsymmetricStartKey( Master_Send_Key, Master_Key, 16, TRUE, TRUE );
  GetAsymmetricStartKey( Master_Receive_Key, Master_Key,  16, FALSE, TRUE );

  /*
   * Specification bug:
   * "For MS-CHAPv2, SSTP Client HLAK = MasterSendKey | MasterReceiveKey"
   * whereas implementation SHOULD be done like
   * For MS-CHAPv2, SSTP Client HLAK = MasterReceiveKey | MasterSendKey
   */
  memcpy(hlak, Master_Receive_Key, 16*sizeof(uint8_t));
  memcpy(hlak+16, Master_Send_Key, 16*sizeof(uint8_t));

  /*
   * Computing CMAC:
   * CMac computation occurs in 2 times:
   * T1 - CMK computation : CMK = HMAC-SHA(key= hlak, msg= SEED|LEN|0x01)
   * T2 - CMac computation: CMac= HMAC-SHA(key= CMK, msg= SSTP_CALL_CONNECTED_MSG_ZEROED)
   *
   * Where SSTP_CALL_CONNECTED_MSG_ZEROED is SSTP_CALL_CONNECTED_MSG with CMAC field
   * filled with 0 (zero)
   */
  ptr = msg;
  memcpy(ptr, SSTP_SEED_PREFIX, strlen(SSTP_SEED_PREFIX));
  ptr += strlen(SSTP_SEED_PREFIX);

  /* T1 */
  /*
   * To generate the Compound MAC Key (CMK), implementations MUST use the HLAK, MUST use the
   * PRF+ seed value as the input to a PRF+ operation, and MUST generate 32 bytes.
   */

  hash_len = (ctx->hash_algorithm==CERT_HASH_PROTOCOL_SHA1) ? SHA1_HASH_LEN : SHA256_HASH_LEN;
  memcpy(ptr, &hash_len, sizeof(uint16_t)); ptr += sizeof(uint16_t);
  *ptr = 0x01; ptr ++;

  if ( (cmk = sstp_hmac(hlak, msg, 32)) == NULL)
    return -1;


  /* T2 */
  /*
   * "[...] the Compound MAC MUST be constructed from the entire 112 bytes of the Call Connected
   * message(section 2.2.11) with the Compound MAC field and Padding field zeroed out."
   */

  ptr = Call_Connected_buffer;
  memcpy(ptr, Call_Connected_header, 16); ptr+= 16;
  memcpy(ptr, ctx->nonce, 32); ptr += 32;
  memcpy(ptr, ctx->certhash, 32); ptr += 32;

  if ( !(cmac = sstp_hmac(cmk, Call_Connected_buffer, 112)) )
    return -1;

  memcpy(ctx->cmk, cmk, 32);
  memcpy(ctx->cmac, cmac, 32);

  xfree(cmk);
  xfree(cmac);


  /* Verbose output displays brief crypto information */
  #ifdef DEBUG
  if (cfg->verbose > 2)
    {

      int i=0;
      char dbg_msg[MAX_LINE_LENGTH];

      /* display hash algorithm */
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t%s (%#2x)\n",
	   "Hash algorithm", crypto_req_attrs_str[ctx->hash_algorithm], ctx->hash_algorithm);

      /* display nonce sent by server for authentication */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for (i=0; i<8; i++) snprintf(dbg_msg+(i*8), 9, "%8x", ntohl(ctx->nonce[i]));
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "Nonce", dbg_msg);

      /* display certificate hash */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for(i=0; i<8; i++) snprintf(dbg_msg+(i*8), 9, "%8x", ntohl(ctx->certhash[i]));
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "CA Hash", dbg_msg);

      /* display T1 message */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for (i=0; i<32; i++) snprintf(dbg_msg+i,3, "%2x", msg[i]);
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "T1 msg", dbg_msg);

      /* display user's password hashed with MD4 */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for (i=0; i<MD4_DIGEST_LENGTH; i++) snprintf(dbg_msg+i, 3, "%2x", PasswordHash[i]);
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "H(Password)", dbg_msg);

      /* display user's password hash hashed with MD4 */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for (i=0; i<MD4_DIGEST_LENGTH; i++) snprintf(dbg_msg+i, 3, "%2x", PasswordHashHash[i]);
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "H(H(Password))", dbg_msg);

      /* display NT Authentication Response code  */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for (i=0; i<24; i++) snprintf(dbg_msg+i, 3, "%2x", NT_Response[i]);
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "NT Response code", dbg_msg);

      /* display Master Key which will be used to generate all session keys */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for (i=0; i<16; i++) snprintf(dbg_msg+i, 3, "%2x", Master_Key[i]);
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "Master Key", dbg_msg);

      /* display Send Key derivated from Master Key */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for (i=0; i<16; i++) snprintf(dbg_msg+i, 3, "%2x", Master_Send_Key[i]);
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "Master Send Key", dbg_msg);

      /* display Receive Key derivated from Master Key */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for (i=0; i<16; i++) snprintf(dbg_msg+i, 3, "%2x", Master_Receive_Key[i]);
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "Master Receive Key", dbg_msg);

      /* display Higher Level Authentication Key */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for (i=0; i<32; i++) snprintf(dbg_msg+i, 3, "%2x", hlak[i]);
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "HLAK", dbg_msg);

      /* display Compound MAC  */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for(i=0; i<8; i++) snprintf(dbg_msg+(i*8), 9, "%8x", ntohl(ctx->cmac[i]));
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "CMac", dbg_msg);

      /* display Compound MAC Key used by PPP */
      memset(dbg_msg, 0, MAX_LINE_LENGTH);
      for(i=0;i<8;i++) snprintf(dbg_msg+(i*8), 9, "%8x", ntohl(ctx->cmk[i]));
      xlog(LOG_DEBUG, "[Crypto debug] %-20s\t0x%s\n", "CMK", dbg_msg);
    }
#endif
  /* disable negociation timer */
  alarm(0);
  ctx->flags &= ~NEGOCIATION_TIMER_RAISED;

  return 0;
}


/**
 * Decode and parse every attribute provided within an SSTP control packet.
 *
 * @param attrnum : number of attributes
 * @param data : pointer to the beginning of attributes buffer
 * @param bytes_to_read : `data` length
 * @return 0 if all good, negative value otherwise
 */
static int sstp_decode_attributes(uint16_t attrnum, void* data, size_t bytes_to_read)
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

      if (bytes_to_read < sizeof(sstp_attribute_header_t))
	{
	  xlog(LOG_ERROR, "Incorrect attribute received. Leaving...\n");
	  return -1;
	}

      attribute_header = (sstp_attribute_header_t*) attr_ptr;
      attribute_id = attribute_header->attribute_id;
      attribute_length = ntohs( attribute_header->packet_length );
      attribute_data = (attr_ptr + sizeof(sstp_attribute_header_t));


      /* checking attribute header*/
      if (bytes_to_read < attribute_length)
      {
              xlog(LOG_ERROR, "Incorrect attribute length (received=%d,announced=%d).\n", bytes_to_read, attribute_length);
              return -1;
      }

      bytes_to_read -= attribute_length;

      if (attribute_id > SSTP_ATTRIB_CRYPTO_BINDING_REQ)
      {
	  xlog(LOG_ERROR, "Incorrect attribute id.\n");
	  return -1;
      }

      /* parsing attribute header */
      if (cfg->verbose > 2)
	{
	  xlog(LOG_DEBUG, "\t\t--> attr_id\t%s (%#.2x)\n",attr_types_str[attribute_id], attribute_id);
	  xlog(LOG_DEBUG, "\t\t--> len\t\t%d bytes\n", attribute_length);
	}

      switch (attribute_id)
	{
	case SSTP_ATTRIB_NO_ERROR:
	  break;

	case SSTP_ATTRIB_STATUS_INFO:
	  retcode = attribute_status_info(attribute_data, attribute_length);
	  break;

	case SSTP_ATTRIB_CRYPTO_BINDING_REQ:
	  retcode = crypto_set_binding(attribute_data);
	  break;

	  /* case not to be treated on client side, ignoring */
	case SSTP_ATTRIB_CRYPTO_BINDING:
	case SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID:
	default:
	  xlog(LOG_ERROR, "Attribute ID %#x is not handled on client side.\n", attribute_id);
	  retcode = -1;
	}

      if (retcode < 0) break;

      /* shifting to next attribute */
      attr_ptr += attribute_length;
      attrnum--;
    }

  return retcode;
}


/**
 * Decodes SSTP packet, checks first its header. If control packet, parse it and load
 * eventual attribute function
 *
 * @param rbuffer : buffer received from SSTP server
 * @param sstp_length : buffer length
 * @return 0 if decoding was successful, negative value otherwise. A special case was done
 * for invalid header since there seems to be a problem with server packet length. In this
 * case, received packet is just dropped.
 */
int sstp_decode(void* rbuffer, ssize_t sstp_length)
{
  sstp_header_t* sstp_header;
  int is_control, retcode;

  sstp_header = (sstp_header_t*) rbuffer;
  if (!is_valid_header(sstp_header, sstp_length))
    {
      xlog(LOG_WARNING, "SSTP packet has invalid header. Dropped\n");
      return 0;
    }

  is_control = is_control_packet(sstp_header);

  if (cfg->verbose > 2)
    xlog(LOG_DEBUG, "\t-> %s packet\n", is_control ? "Control" : "Data");

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


      /* checking control header and control type */
      sstp_length -= sizeof(sstp_control_header_t);
      if (sstp_length < 0)
	{
	  xlog(LOG_ERROR, "SSTP control packet has invalid size\n");
	  return -1;
	}

       if (!control_type || control_type > SSTP_MSG_ECHO_REPONSE)
	{
	  xlog(LOG_ERROR, "Incorrect control packet\n");
	  return -1;
	}


      /* parsing control header */
      if (cfg->verbose > 2)
	{
	  xlog(LOG_DEBUG, "\t-> type: %s (%#.2x)\n",
	       control_messages_types_str[control_type], control_type);
	  xlog(LOG_DEBUG, "\t-> attribute number: %d\n", control_num_attributes);
	  xlog(LOG_DEBUG, "\t-> length: %d\n", (sstp_header->length - sizeof(sstp_header_t)));
	}

      switch (control_type)
	{
	case SSTP_MSG_CALL_CONNECT_ACK:
	  retcode = sstp_decode_attributes(control_num_attributes, attribute_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  break;

	case SSTP_MSG_CALL_CONNECT_NAK:
	  if ( ctx->state==CLIENT_CONNECT_REQUEST_SENT ) return -1;

	  retcode = sstp_decode_attributes(control_num_attributes, attribute_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  if ( ctx->retry )
	    {
	      if (cfg->verbose)
		xlog(LOG_INFO, "Retrying ... (%d/%d)\n",
		     SSTP_MAX_INIT_RETRY - ctx->retry, SSTP_MAX_INIT_RETRY);

	      ctx->negociation_timer.tv_sec = SSTP_NEGOCIATION_TIMER;
	      ctx->retry--;
	      sstp_init();
	    }

	  break;

	case SSTP_MSG_CALL_ABORT:
	  retcode = sstp_decode_attributes(control_num_attributes, attribute_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  set_client_status(CLIENT_CALL_DISCONNECTED);
	  break;

	case SSTP_MSG_CALL_DISCONNECT:
	  retcode = sstp_decode_attributes(control_num_attributes, attribute_ptr, sstp_length);
	  if (retcode < 0) return -1;

	  ctx->flags |= REMOTE_DISCONNECTION;
	  set_client_status(CLIENT_CALL_DISCONNECTED);
	  break;

	case SSTP_MSG_ECHO_REQUEST:
	  if (ctx->state != CLIENT_CALL_CONNECTED) return -1;
	  send_sstp_control_packet(SSTP_MSG_ECHO_REPONSE, NULL, 0, 0);
	  break;

	case SSTP_MSG_ECHO_REPONSE:
	  if (ctx->state != CLIENT_CALL_CONNECTED) return -1;
	  alarm(0);
	  ctx->flags &= ~HELLO_TIMER_RAISED;
	  break;

	case SSTP_MSG_CALL_CONNECT_REQUEST:
	case SSTP_MSG_CALL_DISCONNECT_ACK:
	default :
	  xlog(LOG_ERROR, "Client cannot handle type %#x\n", control_type);
	  set_client_status(CLIENT_CALL_DISCONNECTED);
	  return -1;
	}

    }
  else
    {
      void* data_ptr;
      data_ptr = rbuffer + sizeof(sstp_header_t);

      /*
       * On intercepting a PPP success message, sstoper will also send
       * a SSTP_MSG_CALL_CONNECTED message, allowing PPP data to be treated
       * on server side.
       * See also : http://tools.ietf.org/search/rfc2759#section-4
       */

      if ( ntohs(*((uint16_t*)data_ptr)) == 0xc223 )
	{
	  uint8_t chap_handshake_code = *(uint8_t*)(data_ptr + 2);

	  /* if Success on PPP-CHAP */
	  if (chap_handshake_code == 0x03 )
	    {
	      size_t attribute_len;
	      void* attribute;
	      sstp_attribute_crypto_bind_t crypto_settings;

	      /* compute cmac */
	      if (crypto_set_cmac() < 0)
		return -1;

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

	      xfree(attribute);

	      /* and set hello timer */
	      ctx->flags |= HELLO_TIMER_RAISED;
	      set_client_status(CLIENT_CALL_CONNECTED);
	      alarm(ctx->hello_timer.tv_sec);

	      xlog(LOG_INFO, "SSTP link established\n");

	      /* send an sstp ping, response will stop the alarm */
	      send_sstp_control_packet(SSTP_MSG_ECHO_REQUEST, NULL, 0, 0);
	    }

	  else if (chap_handshake_code == 0x04 )
	    {
	      xlog(LOG_ERROR, "PPP Authentication failure\n");
	    }

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






/**
 * Based on ssl_ppp_fork() in SSLTunnel
 *
 * Prepare pppd options and execute pppd daemon in a fork child. For an obscure
 * reason, probably voodoo, EAP fails while negociation so it has been explicitly
 * deactivated.
 *
 * @return child pid if process is the father or error otherwise (execv pppd)
 */
int sstp_fork()
{
  pid_t ppp_pid;
  int retcode, amaster, aslave, i;
  struct termios pty;
  char *pppd_path;
  char *pppd_args[32];

  pppd_path = cfg->pppd_path;
  i = 0;

  pppd_args[i++] = "pppd";
  pppd_args[i++] = "nodetach";
  pppd_args[i++] = "local";
  pppd_args[i++] = "noauth";
  pppd_args[i++] = "sync";
  pppd_args[i++] = "refuse-eap";
  pppd_args[i++] = "nodeflate";
  /*
  pppd_args[i++] = "mru";
  pppd_args[i++] = "1412";
  */
  pppd_args[i++] = "user";
  pppd_args[i++] = cfg->username;
  pppd_args[i++] = "password";
  pppd_args[i++] = cfg->password;


  if (cfg->logfile != NULL)
    {
      pppd_args[i++] = "logfile";
      pppd_args[i++] = cfg->logfile;
      pppd_args[i++] = "debug";
      pppd_args[i++] = "dump";
    }

  if (cfg->domain != NULL)
    {
      pppd_args[i++] = "domain";
      pppd_args[i++] = cfg->domain;
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
      /* wait for SIGUSR1 from sstoper process */
      sigset_t	newmask, oldmask, zeromask;

      do_loop = TRUE;
      sigemptyset(&zeromask);
      sigemptyset(&newmask);
      sigaddset(&newmask, SIGUSR1);

      if (cfg->verbose > 1)
	xlog(LOG_DEBUG, "[%d] Waiting for SIGUSR1\n", getpid());

      if (sigprocmask(SIG_BLOCK, &newmask, &oldmask) < 0)
	{
	  xlog(LOG_ERROR, "Fail to block SIGMASK\n");
	  return -1;
	}

      while (do_loop)
	{
	  retcode = sigsuspend(&zeromask);

	  if (errno == EFAULT)
	    {
	      xlog(LOG_ERROR, "sstp_fork : sigsuspend failed\n");
	      if (cfg->verbose)
		{
		  xlog(LOG_DEBUG, strerror(errno));
		}
 	      close(sockfd);
	      return -1;
	    };
	}

      /* do_loop = FALSE; */

      if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
	{
	  xlog(LOG_ERROR, "Fail to reset SIGMASK\n");
	  return -1;
	}


      /* close fds */
      close(sockfd);

      dup2(aslave, 0);
      dup2(aslave, 1);

      if (aslave > 2) close (aslave);
      if (amaster > 2) close (amaster);

      if (getuid()!=0)
	{
	  if (setuid(0) < 0)
	    {
	      xlog(LOG_ERROR, "%s\n", strerror(errno));
	      return -1;
	    }

	  /* raise power */
	  if (cfg->verbose > 1)
	    xlog(LOG_DEBUG, "[%d] Promoted to UID %d\n", getpid(), getuid());
	}

      /* spawn pppd */
      if (cfg->verbose > 1)
	{
	  int i = 0, max_len = MAX_LINE_LENGTH;
	  char cmdline[max_len], *ptr=NULL;

	  memset(cmdline, 0, max_len);
	  max_len--;

	  while ((ptr = pppd_args[i++])) {
	    max_len -= strlen(ptr);
	    if (max_len < 0) break;
	    strncat(cmdline, ptr, max_len);

	    max_len--;
	    if (max_len < 0) break;
	    strncat(cmdline, " ", max_len);
	  }
	  xlog(LOG_DEBUG, "execv-ing '%s'\n", cmdline);
	}

      /* yield to pppd */
      if (execv (pppd_path, pppd_args) == -1)
	{
	  xlog (LOG_ERROR, "sstp_fork: execv: %s\n", strerror(errno));
	  return -1;
	}

    }

  else
    {
      xlog (LOG_ERROR, "sstp_fork: you should never be here\n");
      if (cfg->verbose > 1)
	xlog(LOG_ERROR,"FATAL: %s\n", strerror(errno));
      set_client_status(CLIENT_CALL_DISCONNECTED);

      return -1;
    }

  return 0;
}


/**
 * HMAC function wrapper, this function calculates HMAC value of a n-length message
 * with the key `key`. Created HMAC buffered has to be freed later.
 *
 * @param key is the HMAC key
 * @param d is the message to be hashed
 * @param n is `d` string length
 * @return a pointer to HMAC result buffer.
 */
uint8_t* sstp_hmac(unsigned char* key, unsigned char* d, uint16_t n)
{
  uint8_t *md = NULL;
  unsigned int mdlen;
  const EVP_MD* (*hmac)();
  unsigned int hash_len;

  switch (ctx->hash_algorithm)
    {
    case CERT_HASH_PROTOCOL_SHA1:
      hmac = &EVP_sha1;
      hash_len = SHA1_HASH_LEN;
      break;

    case CERT_HASH_PROTOCOL_SHA256:
    default:
      hmac = &EVP_sha256;
      hash_len = SHA256_HASH_LEN;
      break;
    }

  md = (uint8_t*) xmalloc(32);

  if (HMAC(hmac(), key, 32, d, n, md, &mdlen) == NULL)
    {
      xlog(LOG_ERROR, "Failed to compute HMAC\n");
      xfree(md);
      return NULL;
    }

  if (mdlen != hash_len)
    {
      xlog(LOG_ERROR, "%s function didn't return valid data!\n",
	   crypto_req_attrs_str[ctx->hash_algorithm]);
      xfree(md);
      return NULL;
    }

  return md;
}


/**
 * Functions defined below are only used to generate correct CMac value
 * Also see:
 * - http://tools.ietf.org/search/rfc3079
 * - http://tools.ietf.org/search/rfc2759
 */
void NtPasswordHash(uint8_t *password_hash, const uint8_t *password, size_t password_len)
{
  uint8_t buf[512];
  size_t i;
  MD4_CTX c;

  if (password_len > 256)
    {
      password_hash = NULL;
      return;
    }

  memset(buf, 0, 512);
  /* Convert password into Unicode */
  for (i=0; i<password_len; i++)
    buf[i*2] = password[i];


  MD4_Init(&c);
  MD4_Update(&c, buf, password_len * 2);
  MD4_Final(password_hash, &c);
}


void HashNtPasswordHash(uint8_t *password_hash_hash, const uint8_t *password_hash)
{
  MD4_CTX c;
  MD4_Init(&c);
  MD4_Update(&c, password_hash, MD4_DIGEST_LENGTH);
  MD4_Final(password_hash_hash, &c);
}


void GetMasterKey(void* MasterKey, void* PasswordHashHash, void* NTResponse)
{
  SHA_CTX c;
  uint8_t Digest[20];

  /* "Magic" constants used in key derivations */
  static unsigned char Magic1[27] =
    {
      0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
      0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
      0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79
    };

  memset(Digest, 0, sizeof(Digest));

  SHA1_Init(&c);
  SHA1_Update(&c, PasswordHashHash, 16);
  SHA1_Update(&c, NTResponse, 24);
  SHA1_Update(&c, Magic1, 27);
  SHA1_Final(Digest, &c);

  memcpy(MasterKey, Digest, 16);
}


void GetAsymmetricStartKey(void* MasterSessionKey, void* MasterKey,
			   uint8_t KeyLength, uint8_t IsSend, uint8_t IsServer)
{
  uint8_t Digest[20];
  uint8_t *Magic;
  SHA_CTX c;

  /* Pads used in key derivation */
  static unsigned char SHSpad1[40] =
    {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

  static unsigned char SHSpad2[40] =
    {
      0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
      0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
      0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
      0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2
    };

  /* "Magic" constants used in key derivations */
  static unsigned char Magic2[84] =
    {
      0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
      0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
      0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
      0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
      0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
      0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
      0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
      0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
      0x6b, 0x65, 0x79, 0x2e
    };

  static unsigned char Magic3[84] =
    {
      0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
      0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
      0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
      0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
      0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
      0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
      0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
      0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
      0x6b, 0x65, 0x79, 0x2e
    };

  memset(Digest, 0, 20);

  if (IsSend)
    Magic = (IsServer ? Magic3 : Magic2);
  else
    Magic = (IsServer ? Magic2 : Magic3);


  SHA1_Init(&c);
  SHA1_Update(&c, MasterKey, 16);
  SHA1_Update(&c, SHSpad1, 40);
  SHA1_Update(&c, Magic, 84);
  SHA1_Update(&c, SHSpad2, 40);
  SHA1_Final(Digest, &c);

  memcpy(MasterSessionKey, Digest, KeyLength);
}
