#include <stdint.h>

/* SSTP Properties */
#define SSTP_VERSION 0x10
#define SSTP_MIN_LEN 4 
#define SSTP_MAX_ATTR 256
#define __UNSIGNED_LONG_LONG_MAX__ (~0LLU)
#define SSTP_CORRELATION_ID  "{F7FC0718-C386-4D9A-B529-973827075AA7}"
#define BUFFER_SIZE 1024


/* SSTP Packet Type */
enum packet_types 
  {
    SSTP_DATA_PACKET = 0x00,
    SSTP_CONTROL_PACKET = 0x01
  };


/* SSTP Protocol Type */
enum sstp_encapsulated_protocol_types 
  {
    SSTP_ENCAPSULATED_PROTOCOL_PPP = 0x0001
  };


/* SSTP Status Message */
enum control_messages_types
  {
    SSTP_MSG_CALL_CONNECT_REQUEST = 0x0001,
    SSTP_MSG_CALL_CONNECT_ACK = 0x0002,
    SSTP_MSG_CALL_CONNECT_NAK = 0x0003,
    SSTP_MSG_CALL_CONNECTED = 0x0004,
    SSTP_MSG_CALL_ABORT = 0x0005,
    SSTP_MSG_CALL_DISCONNECT = 0x0006,
    SSTP_MSG_CALL_DISCONNECT_ACK = 0x0007,
    SSTP_MSG_ECHO_REQUEST = 0x0008,
    SSTP_MSG_ECHO_RESPONSE = 0x0009
  };


/* SSTP Attribute Message Type */
enum attr_types 
  {
    SSTP_ATTRIB_NO_ERROR = 0x00,
    SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID = 0x01,
    SSTP_ATTRIB_STATUS_INFO = 0x02,
    SSTP_ATTRIB_CRYPTO_BINDING = 0x03,
    SSTP_ATTRIB_CRYPTO_BINDING_REQ = 0x04
  };


/* Crypto Binding Request Attribute */
enum crypto_req_attrs 
  {
    CERT_HASH_PROTOCOL_SHA1 = 0x01,
    CERT_HASH_PROTOCOL_SHA256 = 0x02
  };


/* Status Info Attribute */
enum attr_status 
  {
    ATTRIB_STATUS_NO_ERROR = 0x00000000,
    ATTRIB_STATUS_DUPLICATE_ATTRIBUTE = 0x00000001,
    ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE = 0x00000002,
    ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH = 0x00000003,
    ATTRIB_STATUS_VALUE_NOT_SUPPORTED = 0x00000004,
    ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED = 0x00000005,
    ATTRIB_STATUS_RETRY_COUNT_EXCEEDED = 0x00000006,
    ATTRIB_STATUS_INVALID_FRAME_RECEIVED = 0x00000007,
    ATTRIB_STATUS_NEGOTIATION_TIMEOUT = 0x00000008,
    ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG = 0x00000009,
    ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING = 0x0000000a,
    ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG = 0x0000000b
  };


/* data structures */
typedef struct __sstp_header
{
  uint8_t version;
  uint8_t reserved;
  uint16_t length;
} sstp_header_t; 

typedef struct __sstp_control_header 
{
  uint16_t message_type;
  uint16_t num_attributes;
} sstp_control_header_t; 

typedef struct __sstp_attribute_header 
{
  uint8_t reserved;
  uint8_t attribute_id;
  uint16_t packet_length;
} sstp_attribute_header_t; 

typedef struct __sstp_attribute
{
  uint16_t length;
  void *data;
} sstp_attribute_t;


/* functions declarations  */
void init_sstp(gnutls_session_t*);
int is_control_packet(sstp_header_t*);
void* xmalloc(size_t);
void sstp_send(gnutls_session_t*, void*, size_t);
void sstp_recv(gnutls_session_t*);

sstp_control_header_t* get_sstp_control_header(void* recv_buf);
void sstp_decode(char* recv_buf);
