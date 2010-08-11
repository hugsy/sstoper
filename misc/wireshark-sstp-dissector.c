/*
 * Filename: packet-sstp.c
 * Description: Routines for SSTP dissection
 * Author: Christophe Alladoum <christophe.alladoum@hsc.fr>
 * Licence: GPL v2
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Also see :
 * - MS-SSTP : http://msdn.microsoft.com/en-us/library/cc247338(PROT.10).aspx
 *
 * Requires SSL packet decryption
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <glib.h>
#include <epan/dissectors/packet-ssl.h>
#include <epan/packet.h>


/* SSTP Properties */
#define SSTP_MIN_LEN 4 
#define SSTP_MAX_ATTR 256


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
enum status_messages 
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


/* VALS() structure definitions */
static const value_string packet_types[] =
  {
    {SSTP_DATA_PACKET, "SSTP Data Packet"},
    {SSTP_CONTROL_PACKET, "SSTP Control Packet"},
    {0, NULL }
  };

static const value_string message_types[] =
  {
    {SSTP_MSG_CALL_CONNECT_REQUEST, "SSTP_MSG_CALL_CONNECT_REQUEST"},
    {SSTP_MSG_CALL_CONNECT_ACK, "SSTP_MSG_CALL_CONNECT_ACK"},
    {SSTP_MSG_CALL_CONNECT_NAK, "SSTP_MSG_CALL_CONNECT_NAK"},
    {SSTP_MSG_CALL_CONNECTED, "SSTP_MSG_CALL_CONNECTED"},
    {SSTP_MSG_CALL_ABORT, "SSTP_MSG_CALL_ABORT"},
    {SSTP_MSG_CALL_DISCONNECT, "SSTP_MSG_CALL_DISCONNECT"},
    {SSTP_MSG_CALL_DISCONNECT_ACK, "SSTP_MSG_CALL_DISCONNECT_ACK"},
    {SSTP_MSG_ECHO_REQUEST, "SSTP_MSG_ECHO_REQUEST" },
    {SSTP_MSG_ECHO_RESPONSE, "SSTP_MSG_ECHO_RESPONSE" },
    {0, NULL }
  };

static const value_string attributes_ids[] =
  {
    {SSTP_ATTRIB_NO_ERROR, "SSTP_ATTRIB_NO_ERROR"},
    {SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID, "SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID"},
    {SSTP_ATTRIB_STATUS_INFO, "SSTP_ATTRIB_STATUS_INFO"},
    {SSTP_ATTRIB_CRYPTO_BINDING, "SSTP_ATTRIB_CRYPTO_BINDING"},
    {SSTP_ATTRIB_CRYPTO_BINDING_REQ, "SSTP_ATTRIB_CRYPTO_BINDING_REQ"},
    {0, NULL }
  };

static const value_string encapsulated_protocol_id_ids[] =
  {
    { SSTP_ENCAPSULATED_PROTOCOL_PPP, "SSTP_ENCAPSULATED_PROTOCOL_PPP" },
    {0, NULL }
  };

static const value_string hash_protocol_bitmasks[] = 
  {
    {CERT_HASH_PROTOCOL_SHA1, "CERT_HASH_PROTOCOL_SHA1"}, 
    {CERT_HASH_PROTOCOL_SHA256, "CERT_HASH_PROTOCOL_SHA256"},
    {0, NULL }    
  };
      
static const value_string status_info[] =
  {
    {ATTRIB_STATUS_NO_ERROR, "ATTRIB_STATUS_NO_ERROR"},
    {ATTRIB_STATUS_DUPLICATE_ATTRIBUTE, "ATTRIB_STATUS_DUPLICATE_ATTRIBUTE"},
    {ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE, "ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE"},
    {ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH, "ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH"},
    {ATTRIB_STATUS_VALUE_NOT_SUPPORTED, "ATTRIB_STATUS_VALUE_NOT_SUPPORTED"},
    {ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED, "ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED"}, 
    {ATTRIB_STATUS_RETRY_COUNT_EXCEEDED, "ATTRIB_STATUS_RETRY_COUNT_EXCEEDED"},
    {ATTRIB_STATUS_INVALID_FRAME_RECEIVED, "ATTRIB_STATUS_INVALID_FRAME_RECEIVED"},
    {ATTRIB_STATUS_NEGOTIATION_TIMEOUT, "ATTRIB_STATUS_NEGOTIATION_TIMEOUT"},
    {ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG, "ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG"},
    {ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING, "ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING"}, 
    {ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG, "ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG"},
    {0, NULL }
  };

/* Functions declaration */
void proto_reg_handoff_sstp(void);
void proto_register_sstp(void);
gboolean is_control_message(tvbuff_t *tvb);

/* Initialize the protocol and registered fields */
static int proto_sstp = -1;

static gboolean is_sstp_conversation = FALSE;


/* SSTP is based on HTTP over SSL (TCP/443) */
static guint HTTPS_PORT = 443;

/* Initialize the subtree pointers */
static gint ett_sstp = -1;
static gint ett_sub_sstp = -1;

/* Generic headers attributes */
static int hf_sstp_version = -1;
static int hf_sstp_control = -1;
static int hf_sstp_length = -1;

/* SSTP Data Field */
static int hf_sstp_data = -1;

/* SSTP Control Packet generic headers */
static int hf_sstp_ctrl_type = -1; 
static guint hf_sstp_ctrl_attrnum = -1;


/* SSTP Control Attribute Field */

/* SSTP Control Packet generic headers */
static int hf_sstp_ctrl_attr_id  = -1;
static int hf_sstp_ctrl_attr_plen  = -1;

/* Encapsulated Protocol ID Attribute properties */
static int hf_sstp_ctrl_attr_encapsulated_protocol_id = -1;

/* Status Info Attribute properties */
static int hf_sstp_ctrl_attr_attrid = -1;
static int hf_sstp_ctrl_attr_status_info = -1;
static int hf_sstp_ctrl_attr_status_value = -1;

/* Crypto Binding Request Attribute properties */
static int hf_sstp_ctrl_attr_cryptreq_hash_bitmask = -1;
static guint32 hf_sstp_ctrl_attr_cryptreq_nonce = -1;

/* Crypto Binding Attribute properties */
static guint32 hf_sstp_ctrl_attr_cert_hash = -1;
static guint32 hf_sstp_ctrl_attr_compound_mac = -1;


static guint encapsulated_protocol = -1;


/* Returns True (1) if packet is a control packet */
gboolean is_control_message(tvbuff_t *tvb) 
{
  guint8 packet_type;
  packet_type = tvb_get_guint8(tvb, 1);
  return packet_type & 1;
}

/* Parsing all attributes */ 
static void parse_attributes(tvbuff_t *tvb, proto_tree *parent, guint offset, guint16 nb_attr)
{
  guint attribute_number = 0;

  nb_attr = MIN(nb_attr, SSTP_MAX_ATTR);
    
  while (attribute_number < nb_attr)
    {
      guint8 attr_id;
      guint16 attr_plen;
      guint32 status;
      guint hash_bitmask;

      proto_tree* attr_tree;
      proto_item* item;
      
      /* create subtree for the attribute */
      attr_tree = proto_item_add_subtree(parent, ett_sub_sstp);

      /* skipping 'Reserved' field */
      offset ++;

      /* ID attribute */
      proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_id, tvb, offset, 1, FALSE);
      attr_id = tvb_get_guint8(tvb, offset);
      offset ++;

      /* Length Packet attribute */
      item = proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_plen, tvb, offset, 2, FALSE);
      attr_plen = tvb_get_ntohs(tvb, offset) & 0x0fff;
      proto_item_append_text(item, " bytes");
      offset += 2;

      /* Parsing attribute field according to its type */
      switch (attr_id)
	{
		  
	case SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID:
	  /* Encapsulated Protocol ID */
	  proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_encapsulated_protocol_id, tvb, offset, 2, FALSE);
	  encapsulated_protocol = tvb_get_ntohs(tvb, offset);
	  offset += 2;
	  
	  break;

	case SSTP_ATTRIB_STATUS_INFO:
	  /* skipping 'Reserved1' field */
	  offset += 3;

	  /* AttrID */
	  proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_attrid, tvb, offset, 1, FALSE);
	  offset ++;
	  
	  /* Parsing 'Status' field */ 
	  proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_status_info, tvb, offset, 4, FALSE);
	  status = tvb_get_ntohl(tvb, offset);
	  offset += 4;

	  /* Parsing 'AttribValue' field */
	  if (status != ATTRIB_STATUS_NO_ERROR) 
	    {
	      proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_status_value, tvb, offset, 64, FALSE);
	      offset += 64;
	    }
	  
	  break;

	case SSTP_ATTRIB_CRYPTO_BINDING_REQ:
	  /* Skipping 'Reserved1' field */
	  offset += 3;

	  /* Hash Protocol Bitmask */
	  proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_cryptreq_hash_bitmask, tvb, offset, 1, FALSE);
	  offset ++;

	  /* Nonce */
	  proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_cryptreq_nonce, tvb, offset, 32, FALSE);
	  offset += 32;
	  
	  break;

	case SSTP_ATTRIB_CRYPTO_BINDING:
	  /* Skipping 'Reserved1' field */
	  offset += 3;
	  
	  /* Hash Protocol Bitmask */
	  proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_cryptreq_hash_bitmask, tvb, offset, 1, FALSE);
	  hash_bitmask = tvb_get_guint8(tvb, offset);
	  offset ++;
	  
	  /* Nonce */	    
	  proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_cryptreq_nonce, tvb, offset, 32, FALSE);
	  offset += 32;
	  
	  /* Cert Hash */
	  if (hash_bitmask & CERT_HASH_PROTOCOL_SHA1) 
	    {
	      proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_cert_hash, tvb, offset, 20, FALSE);
	      offset += 20;
	    }
	  else if (hash_bitmask & CERT_HASH_PROTOCOL_SHA256) 
	    {
	      proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_cert_hash, tvb, offset, 32, FALSE);
	      offset += 32;			
	    }
	  else 
	    {
	      /* INVALID CASE : goto next attribute (default behaviour) */
	      /* Rollback and jump to next attribute  */
	      offset -= 36;
	      offset += attr_plen;
	    }
	  
	  /* Adding the 'Padding' if SHA1 */
	  if (hash_bitmask & CERT_HASH_PROTOCOL_SHA1)
	    offset += 12;
	  
	  /* Compound MAC according to hash_bitmask value */
	  if (hash_bitmask & CERT_HASH_PROTOCOL_SHA1) 
	    {
	      proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_compound_mac, tvb, offset, 20, FALSE);
	      offset += 20;
	    }
	  else if (hash_bitmask & CERT_HASH_PROTOCOL_SHA256) 
	    {
	      proto_tree_add_item(attr_tree, hf_sstp_ctrl_attr_compound_mac, tvb, offset, 32, FALSE);
	      offset += 32;			
	    }
	  else 
	    {
	      /* INVALID CASE : goto next attribute (default behaviour) */
	      /* Rollback and jump to next attribute  */
	      offset -= 58; 
	      offset += attr_plen;
	    }
	  
	  /* Considering the 'Padding1' reserved field (not interpreted) */
	  if (hash_bitmask & CERT_HASH_PROTOCOL_SHA1)
	    offset += 12;
	  
	  break;
	  
	default:
	  /* if unknown goto next attribute */
	  offset -= 4; 
	  offset += attr_plen;
	  break;
	  
	}
		
      attribute_number ++;
    }
}

/* Code to actually dissect the packets */
static void dissect_sstp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
  guint8* head;
  guint len;

  proto_item *ti, *item, *parent;
  proto_tree *sstp_tree, *attr_tree;
  guint offset;
  guint8 value;
  guint16 length;

  guint16 nb_attr;
  guint16 type;
  
  dissector_handle_t next_protocol_handler;
  tvbuff_t *next_tvb;

  
  head = NULL;
  len = 0;
  
  /* Check that there's enough data */
  len = tvb_length(tvb);
  if (len < SSTP_MIN_LEN)
    return ;

  next_protocol_handler = NULL;
  next_tvb = NULL;

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SSTP");

  /* Check that it is an SSTP conversation */
  head = tvb_get_string(tvb, 0, 4); 
    
  if ( strncmp(head, "SSTP", 4) == 0 )
    {
      g_free(head);
      is_sstp_conversation = TRUE;
      return;
    }
  else if ( strncmp(head, "HTTP", 4) == 0 )
    {
      g_free(head);
      return;
    }
  else 
    {
      g_free(head);
    }

  if (is_sstp_conversation == FALSE)
    return;
  
  
  if (tree) {
     ti = NULL;
     sstp_tree = attr_tree = NULL;

     /* initializing offset */
     offset = 0;

     
    /* create main display subtree */
    ti = proto_tree_add_item(tree, proto_sstp, tvb, 0, -1, FALSE);
    sstp_tree = proto_item_add_subtree(ti, ett_sstp);

    
    /* version */
    item  = proto_tree_add_item(sstp_tree, hf_sstp_version, tvb, offset, 1, FALSE);
    value = tvb_get_guint8(tvb, offset);

    proto_item_append_text(item, ", major: %d, minor: %d",
			   (value & 0xf0) >> 4,
			   value & 0x0f);
    
    offset ++;

    /* ctrl */
    proto_tree_add_item(sstp_tree, hf_sstp_control, tvb, offset, 1, FALSE);
    offset ++;

    /* length */ 
    item = proto_tree_add_item(sstp_tree, hf_sstp_length, tvb, offset, 2, FALSE);
    length = tvb_get_ntohs(tvb, offset) & 0x0fff;
    proto_item_append_text(item, " bytes");
    offset += 2;
    
    if (is_control_message(tvb))
      {
	
	/* display header  */
	parent = proto_tree_add_item(sstp_tree, hf_sstp_ctrl_type, tvb, offset, 2, FALSE);
	type = tvb_get_ntohs(tvb, offset) - 1;
	
	col_add_fstr(pinfo->cinfo, COL_INFO, "Control Packet: %s", message_types[type].strptr );

	offset += 2;
	
	proto_tree_add_item(sstp_tree, hf_sstp_ctrl_attrnum, tvb, offset, 2, FALSE);
	nb_attr = tvb_get_ntohs(tvb, offset);
	
	offset += 2;

	proto_item_append_text(ti, ", %d %s",
			       nb_attr,
			       (nb_attr>1) ? "attributes" : "attribute");
	
	/* if there is any attribute in the packet */
	if (nb_attr > 0) 
	  parse_attributes(tvb, parent, offset, nb_attr);
	
      }
    else 
      {
	next_protocol_handler = NULL;
	
	proto_item_append_text(ti, ", length : %d bytes", len);
	
	switch (encapsulated_protocol)
	  {
	  case SSTP_ENCAPSULATED_PROTOCOL_PPP:
	    next_protocol_handler = find_dissector("ppp");
	    break;

	  default:
	    next_protocol_handler = NULL;
	    break;
	  }

	if (next_protocol_handler != NULL) 
	  {
	    next_tvb = tvb_new_subset(tvb, offset, -1, -1);
	    call_dissector(next_protocol_handler, next_tvb, pinfo, proto_tree_get_root(tree));
	  } else 
	  {
	    proto_tree_add_item(sstp_tree, hf_sstp_data, tvb, offset, -1, FALSE);	    
	  }
	
      }
    
  } /* end of if(tree) */

}


/* Register the protocol with Wireshark */

void proto_register_sstp(void) 
{
  module_t *sstp_module;

  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    { &hf_sstp_version,
      { "Version",  "sstp.version",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	"SSTP version field", HFILL }
    },

    { &hf_sstp_control,
      { "Control Byte",  "sstp.control",
	FT_UINT8, BASE_DEC, VALS(packet_types), 0x0,
	"SSTP Control Field", HFILL }
    },

    { &hf_sstp_length,
      { "Total length",  "sstp.length",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"SSTP packet size", HFILL }
    },

    { &hf_sstp_ctrl_type,
      { "Control Message Type",  "sstp.ctrl_type",
	FT_UINT16, BASE_DEC, VALS(message_types), 0x0,
	"SSTP Control Message Type", HFILL }
    },

    { &hf_sstp_ctrl_attrnum,
      { "Number of Attribute",  "sstp.ctrl_attrnum",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"SSTP Control Message Attribute length", HFILL }
    },

    { &hf_sstp_ctrl_attr_id,
      { "Attribute Id",  "sstp.ctrl_attr_id",
	FT_UINT8, BASE_DEC, VALS(attributes_ids), 0x0,
	"SSTP Control Message Attribute Identifier", HFILL }
    },

    { &hf_sstp_ctrl_attr_plen,
      { "Attribute Length",  "sstp.ctrl_attr_plen",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	"SSTP Control Message Attribute Packet Length", HFILL }
    },
 
    { &hf_sstp_ctrl_attr_attrid,
      { "Control Message AttrID", "sstp.ctrl_attr_attrid",
	FT_UINT8, BASE_DEC, VALS(attributes_ids), 0x0,	
	"SSTP Control Message AttrID", HFILL }
    },

    { &hf_sstp_ctrl_attr_status_info,
      { "Control Message Attribute Status", "sstp.ctrl_attr_status_info",
	FT_UINT32, BASE_HEX, VALS(status_info), 0x0,
	"SSTP Control Message Attribute Status Information", HFILL }
    },
    
    { &hf_sstp_ctrl_attr_status_value,
      { "Control Message Attribute Status", "sstp.ctrl_attr_status_value",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	"SSTP Control Message Attribute Value", HFILL }
    },
    
    { &hf_sstp_ctrl_attr_encapsulated_protocol_id,
      { "Encapsulated Protocol ID", "sstp.encapsulated_protocol_id",
	FT_UINT16, BASE_DEC, VALS(encapsulated_protocol_id_ids), 0x0,
	"SSTP Encapsulated Protocol ID", HFILL }
    },
    
    { &hf_sstp_ctrl_attr_cryptreq_hash_bitmask,
      { "Hash Algorithm Bitmask", "sstp.ctrl_attr_cryptreq_hash_bitmask",
	FT_UINT32, BASE_DEC, VALS(hash_protocol_bitmasks), 0x0,
	"SSTP Crypto Binding Supported Hash Algorithm Bitmask", HFILL }
    },
    
    { &hf_sstp_ctrl_attr_cryptreq_nonce,
      { "Nonce",  "sstp.ctrl_attr_cryptreq_nonce",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"SSTP Crypto Binding Connect Negociation Nonce", HFILL }
    },

    { &hf_sstp_ctrl_attr_cert_hash,
      { "Cert Hash",  "sstp.ctrl_attr_cert_hash",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"SSTP Crypto Binding Cert Hash Attribute", HFILL }
    },

    { &hf_sstp_ctrl_attr_compound_mac,
      { "Compound Mac",  "sstp.ctrl_attr_compound_mac",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"SSTP Crypto Binding Compound Mac Attribute", HFILL }
    },   

    { &hf_sstp_data,
      {	"Data", "sstp.data",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	"SSTP Encrypted data", HFILL }
    },
    
  };

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_sstp    
  };

  static gint *ett_subtree[] = {
    &ett_sub_sstp
  };

  
  /* Register the protocol name and description */
  proto_sstp = proto_register_protocol("Secure Socket Tunneling Protocol",
				       "SSTP", 
				       "sstp");
  
  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_sstp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  proto_register_subtree_array(ett_subtree, array_length(ett_subtree));
  
  register_dissector("sstp", dissect_sstp, proto_sstp);
  sstp_module = prefs_register_protocol(proto_sstp, proto_reg_handoff_sstp);
}


void proto_reg_handoff_sstp(void)
{
  static dissector_handle_t sstp_handle;
  
  sstp_handle = find_dissector("sstp");
  ssl_dissector_add(HTTPS_PORT, "sstp", TRUE);
}

