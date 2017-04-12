/* packet-epl.c
 * Routines for "Ethernet POWERLINK 2.0" dissection
 * (Ethernet POWERLINK V2.0 Communication Profile Specification Draft Standard Version 1.2.0)
 *
 * Copyright (c) 2006: Zurich University of Applied Sciences Winterthur (ZHW)
 *                     Institute of Embedded Systems (InES)
 *                     http://ines.zhwin.ch
 *
 *                     - Dominic Bechaz <bdo[AT]zhwin.ch>
 *                     - Damir Bursic <bum[AT]zhwin.ch>
 *                     - David Buechi <bhd[AT]zhwin.ch>
 *
 * Copyright (c) 2007: SYS TEC electronic GmbH
 *                     http://www.systec-electronic.com
 *                     - Daniel Krueger <daniel.krueger[AT]systec-electronic.com>
 *
 * Copyright (c) 2013: B&R Industrieelektronik GmbH
 *                     http://www.br-automation.com
 *
 *                     - Christoph Schlosser <christoph.schlosser[AT]br-automation.com>
 *                     - Lukas Emersberger <lukas.emersberger[AT]br-automation.com>
 *                     - Josef Baumgartner <josef.baumgartner[AT]br-automation.com>
 *                     - Roland Knall <roland.knall[AT]br-automation.com>
 *                       - Extended to be similair in handling as to B&R plugin
 *                       - Multiple SOD Read/Write dissection
 *                       - Include AInv message type
 *                       - Straighten text formatting
 *                       - Remove unneccessary if(tree) checks
 *
 * Copyright (c) 2017: Karlsruhe Institute of Technology (KIT)
 *                     Institute for Anthropomatics and Robotics (IAR)
 *                     Intelligent Process Control and Robotics (IPR)
 *                     http://rob.ipr.kit.edu/
 *
 *                     - Ahmad Fatoum <ahmad[AT]a3f.at>
 *                       - Converted into plugin for easier development
 *                       - ObjectMappings now used for dissecting PDOs
 *                       - XDD/EDS files can be read for name/type information
 *
 * A dissector for:
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include "packet-epl.h"
#ifdef HAVE_LIBXML2
	#include "xdd.h"
	#define IF_LIBXML(x) x
#else /* !HAVE_LIBXML2 */
	#define IF_LIBXML(x)
#endif /* !HAVE_LIBXML2 */
#include "eds.h"
#include "wmem_iarray.h"

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/proto_data.h>
#include <epan/uat.h>
#include <wsutil/file_util.h>
#include <wsutil/report_err.h>
#include <glib.h>
#include <string.h>
#include <errno.h>


void proto_register_epl(void);
void proto_reg_handoff_epl(void);

#ifndef UDP_PORT_EPL
#define UDP_PORT_EPL            3819
#endif

/* Allow heuristic dissection and ASND manufacturer dissection */
static heur_dissector_list_t heur_epl_subdissector_list;
static heur_dissector_list_t heur_epl_data_subdissector_list;
static dissector_table_t     epl_asnd_dissector_table;
#if 0
/* Container for tapping relevant data */
typedef struct _epl_info_t {
	unsigned char epl_mtyp;
} epl_info_t;
#endif

/*EPL Addressing*/
#define EPL_DYNAMIC_NODEID                        0
#define EPL_MN_NODEID                           240
#define EPL_DIAGNOSTIC_DEVICE_NODEID            253
#define EPL_TO_LEGACY_ETHERNET_ROUTER_NODEID    254
#define EPL_BROADCAST_NODEID                    255
#define EPL_IS_CN_NODEID(nodeid) (EPL_DYNAMIC_NODEID < (nodeid) && (nodeid) < EPL_MN_NODEID)

static const value_string addr_str_vals[] = {
	{EPL_DYNAMIC_NODEID,                    " (Dynamically assigned)"           },
	{EPL_MN_NODEID,                         " (Managing Node)"                  },
	{EPL_DIAGNOSTIC_DEVICE_NODEID,          " (Diagnostic Device)"              },
	{EPL_TO_LEGACY_ETHERNET_ROUTER_NODEID,  " (POWERLINK to legacy Ethernet Router)"  },
	{EPL_BROADCAST_NODEID,                  " (broadcast)"                      },
	{0,NULL}
};

static const value_string addr_str_abbr_vals[] _U_ = {
	{EPL_DYNAMIC_NODEID,                    " (dyn.)"   },
	{EPL_MN_NODEID,                         " (MN)"     },
	{EPL_DIAGNOSTIC_DEVICE_NODEID,          " (diag.)"  },
	{EPL_TO_LEGACY_ETHERNET_ROUTER_NODEID,  " (router)" },
	{EPL_BROADCAST_NODEID,                  " (bc)"     },
	{0,NULL}
};
/*
static const gchar* addr_str_abbr_cn  = " (CN)";
static const gchar* addr_str_abbr_res = " (res.)";
*/



/* Offsets of fields within an EPL packet. */
#define EPL_MTYP_OFFSET             0   /* same offset for all message types*/
#define EPL_DEST_OFFSET             1   /* same offset for all message types*/
#define EPL_SRC_OFFSET              2   /* same offset for all message types*/

#define EPL_SOA_SVID_OFFSET         6
#define EPL_SOA_SVTG_OFFSET         7
#define EPL_SOA_EPLV_OFFSET         8
/* SyncRequest */
#define EPL_SOA_SYNC_OFFSET         10
#define EPL_SOA_PRFE_OFFSET         14
#define EPL_SOA_PRSE_OFFSET         18
#define EPL_SOA_MNDF_OFFSET         22
#define EPL_SOA_MNDS_OFFSET         26
#define EPL_SOA_PRTO_OFFSET         30
#define EPL_SOA_DEST_OFFSET         34

#define EPL_ASND_SVID_OFFSET        3
#define EPL_ASND_DATA_OFFSET        4
/* NMT Command DNA size */
#define EPL_SIZEOF_NMTCOMMAND_DNA   27

/* EPL message types */
#define EPL_SOC     0x01
#define EPL_PREQ    0x03
#define EPL_PRES    0x04
#define EPL_SOA     0x05
#define EPL_ASND    0x06
#define EPL_AMNI    0x07
#define EPL_AINV    0x0D

static const value_string mtyp_vals[] = {
	{EPL_SOC,  "Start of Cycle (SoC)"         },
	{EPL_PREQ, "PollRequest (PReq)"           },
	{EPL_PRES, "PollResponse (PRes)"          },
	{EPL_SOA,  "Start of Asynchronous (SoA)"  },
	{EPL_ASND, "Asynchronous Send (ASnd)"     },
	{EPL_AINV, "Asynchronous Invite (AInv)"   },
	{EPL_AMNI, "ActiveManagingNodeIndication (AMNI)" },
	{0,NULL}
};

#define EPL_SOC_MC_MASK              0x80
#define EPL_SOC_PS_MASK              0x40
#define EPL_PDO_RD_MASK              0x01

#define EPL_PDO_RS_MASK              0x07
#define EPL_PDO_PR_MASK              0x38

/* RequestedServiceID s for EPL message type "SoA" */
#define EPL_SOA_NOSERVICE               0
#define EPL_SOA_IDENTREQUEST            1
#define EPL_SOA_STATUSREQUEST           2
#define EPL_SOA_NMTREQUESTINVITE        3
#define EPL_SOA_SYNCREQUEST             6
#define EPL_SOA_UNSPECIFIEDINVITE     255

#define EPL_SOA_SYNC_PRES_FIRST         0x01
#define EPL_SOA_SYNC_PRES_SECOND        0x02
#define EPL_SOA_SYNC_MND_FIRST          0x04
#define EPL_SOA_SYNC_MND_SECOND         0x08
#define EPL_SOA_SYNC_PRES_TIMEOUT       0x10
#define EPL_SOA_SYNC_MAC_VALID          0x20
#define EPL_SOA_SYNC_PRES_RESET         0x40
#define EPL_SOA_SYNC_PRES_SET           0x80

static const range_string soa_svid_vals[] = {
	{EPL_SOA_NOSERVICE,         EPL_SOA_NOSERVICE,          "NoService"},
	{EPL_SOA_IDENTREQUEST,      EPL_SOA_IDENTREQUEST,       "IdentRequest"},
	{EPL_SOA_STATUSREQUEST,     EPL_SOA_STATUSREQUEST,      "StatusRequest"},
	{EPL_SOA_NMTREQUESTINVITE,  EPL_SOA_NMTREQUESTINVITE,   "NMTRequestInvite"},
	{0x04,                      0x05,                       "Reserved"},
	{EPL_SOA_SYNCREQUEST,       EPL_SOA_SYNCREQUEST,        "SyncRequest"},
	{0x07,                      0x9F,                       "Reserved"},
	{0xA0,                      0xFE,                       "Manufacturer Specific"},
	{EPL_SOA_UNSPECIFIEDINVITE, EPL_SOA_UNSPECIFIEDINVITE,  "UnspecifiedInvite"},
	{0,                         0,                          NULL}
};

/* ServiceID values for EPL message type "ASnd" */
#define EPL_ASND_IDENTRESPONSE          1
#define EPL_ASND_STATUSRESPONSE         2
#define EPL_ASND_NMTREQUEST             3
#define EPL_ASND_NMTCOMMAND             4
#define EPL_ASND_SDO                    5
#define EPL_ASND_SYNCRESPONSE           6

#define EPL_ASND_SYNCRESPONSE_FST_VALID    0x01
#define EPL_ASND_SYNCRESPONSE_SEC_VALID    0x02
#define EPL_ASND_SYNCRESPONSE_MODE         0x80

static const range_string soa_svid_id_vals[] = {
	{EPL_SOA_NOSERVICE,         EPL_SOA_NOSERVICE,          "NO_SERVICE"},
	{EPL_SOA_IDENTREQUEST,      EPL_SOA_IDENTREQUEST,       "IDENT_REQUEST"},
	{EPL_SOA_STATUSREQUEST,     EPL_SOA_STATUSREQUEST,      "STATUS_REQUEST"},
	{EPL_SOA_NMTREQUESTINVITE,  EPL_SOA_NMTREQUESTINVITE,   "NMT_REQUEST_INV"},
	{0x04,                      0x05,                       "RESERVED"},
	{EPL_SOA_SYNCREQUEST,       EPL_SOA_SYNCREQUEST,        "SYNC_REQUEST"},
	{0x07,                      0x9F,                       "RESERVED"},
	{0xA0,                      0xFE,                       "MANUFACTURER SPECIFIC"},
	{EPL_SOA_UNSPECIFIEDINVITE, EPL_SOA_UNSPECIFIEDINVITE,  "UNSPEC_INVITE"},
	{0,                         0,                          NULL}
};

static const range_string asnd_svid_vals[] = {
	{0,                       0,                       "Reserved"},
	{EPL_ASND_IDENTRESPONSE,  EPL_ASND_IDENTRESPONSE,  "IdentResponse"},
	{EPL_ASND_STATUSRESPONSE, EPL_ASND_STATUSRESPONSE, "StatusResponse"},
	{EPL_ASND_NMTREQUEST,     EPL_ASND_NMTREQUEST,     "NMTRequest"},
	{EPL_ASND_NMTCOMMAND,     EPL_ASND_NMTCOMMAND,     "NMTCommand"},
	{EPL_ASND_SDO,            EPL_ASND_SDO,            "SDO"},
	{EPL_ASND_SYNCRESPONSE,   EPL_ASND_SYNCRESPONSE,   "SyncResponse"},
	{0x07,                    0x9F,                    "Reserved"},
	{0xA0,                    0xFE,                    "Manufacturer Specific"},
	{0xFF,                    0xFF,                    "Reserved"},
	{0,                       0,                        NULL}
};

static const range_string asnd_svid_id_vals[] = {
	{0,                       0,                       "RESERVED"},
	{EPL_ASND_IDENTRESPONSE,  EPL_ASND_IDENTRESPONSE,  "IDENT_RESPONSE"},
	{EPL_ASND_STATUSRESPONSE, EPL_ASND_STATUSRESPONSE, "STATUS_RESPONSE"},
	{EPL_ASND_NMTREQUEST,     EPL_ASND_NMTREQUEST,     "NMT_REQUEST"},
	{EPL_ASND_NMTCOMMAND,     EPL_ASND_NMTCOMMAND,     "NMT_COMMAND"},
	{EPL_ASND_SDO,            EPL_ASND_SDO,            "SDO"},
	{EPL_ASND_SYNCRESPONSE,   EPL_ASND_SYNCRESPONSE,   "SYNC_RESPONSE"},
	{0x07,                    0x9F,                    "RESERVED"},
	{0xA0,                    0xFE,                    "MANUFACTURER SPECIFIC"},
	{0xFF,                    0xFF,                    "RESERVED"},
	{0,                       0,                        NULL}
};

/* NMTCommand values for EPL message type "ASnd" */
#define EPL_ASND_NMTCOMMAND_NMTSTARTNODE                0x21
#define EPL_ASND_NMTCOMMAND_NMTSTOPNODE                 0x22
#define EPL_ASND_NMTCOMMAND_NMTENTERPREOPERATIONAL2     0x23
#define EPL_ASND_NMTCOMMAND_NMTENABLEREADYTOOPERATE     0x24
#define EPL_ASND_NMTCOMMAND_NMTRESETNODE                0x28
#define EPL_ASND_NMTCOMMAND_NMTRESETCOMMUNICATION       0x29
#define EPL_ASND_NMTCOMMAND_NMTRESETCONFIGURATION       0x2A
#define EPL_ASND_NMTCOMMAND_NMTSWRESET                  0x2B
#define EPL_ASND_NMTCOMMAND_NMTDNA                      0x2D

#define EPL_ASND_NMTCOMMAND_NMTSTARTNODEEX              0x41
#define EPL_ASND_NMTCOMMAND_NMTSTOPNODEEX               0x42
#define EPL_ASND_NMTCOMMAND_NMTENTERPREOPERATIONAL2EX   0x43
#define EPL_ASND_NMTCOMMAND_NMTENABLEREADYTOOPERATEEX   0x44
#define EPL_ASND_NMTCOMMAND_NMTRESETNODEEX              0x48
#define EPL_ASND_NMTCOMMAND_NMTRESETCOMMUNICATIONEX     0x49
#define EPL_ASND_NMTCOMMAND_NMTRESETCONFIGURATIONEX     0x4A
#define EPL_ASND_NMTCOMMAND_NMTSWRESETEX                0x4B

#define EPL_ASND_NMTCOMMAND_NMTNETHOSTNAMESET           0x62
#define EPL_ASND_NMTCOMMAND_NMTFLUSHARPENTRY            0x63
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHCONFIGUREDNODES   0x80
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHACTIVENODES       0x90
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHPREOPERATIONAL1   0x91
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHPREOPERATIONAL2   0x92
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHREADYTOOPERATE    0x93
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHOPERATIONAL       0x94
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHSTOPPED           0x95
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHEMERGENCYNEW      0xA0
#define EPL_ASND_NMTCOMMAND_NMTPUBLISHTIME              0XB0
#define EPL_ASND_NMTCOMMAND_NMTINVALIDSERVICE           0xFF

static const value_string asnd_cid_vals[] = {
	/* "special" values to cover all possibilities of CommandID in NMTRequests */
	{EPL_ASND_IDENTRESPONSE,                          "IdentResponse"             },
	{EPL_ASND_STATUSRESPONSE,                         "StatusResponse"            },
	/* ... */
	{EPL_ASND_NMTCOMMAND_NMTSTARTNODE,                "NMTStartNode"              },
	{EPL_ASND_NMTCOMMAND_NMTSTOPNODE,                 "NMTStopNode"               },
	{EPL_ASND_NMTCOMMAND_NMTENTERPREOPERATIONAL2,     "NMTEnterPreOperational2"   },
	{EPL_ASND_NMTCOMMAND_NMTENABLEREADYTOOPERATE,     "NMTEnableReadyToOperate"   },
	{EPL_ASND_NMTCOMMAND_NMTRESETNODE,                "NMTResetNode"              },
	{EPL_ASND_NMTCOMMAND_NMTRESETCOMMUNICATION,       "NMTResetCommunication"     },
	{EPL_ASND_NMTCOMMAND_NMTRESETCONFIGURATION,       "NMTResetConfiguration"     },
	{EPL_ASND_NMTCOMMAND_NMTSWRESET,                  "NMTSwReset"                },
	{EPL_ASND_NMTCOMMAND_NMTDNA,                      "NMTDNA"                    },
	{EPL_ASND_NMTCOMMAND_NMTSTARTNODEEX,              "NMTStartNodeEx"            },
	{EPL_ASND_NMTCOMMAND_NMTSTOPNODEEX,               "NMTStopNodeEx"             },
	{EPL_ASND_NMTCOMMAND_NMTENTERPREOPERATIONAL2EX,   "NMTEnterPreOperational2Ex" },
	{EPL_ASND_NMTCOMMAND_NMTENABLEREADYTOOPERATEEX,   "NMTEnableReadyToOperateEx" },
	{EPL_ASND_NMTCOMMAND_NMTRESETNODEEX,              "NMTResetNodeEx"            },
	{EPL_ASND_NMTCOMMAND_NMTRESETCOMMUNICATIONEX,     "NMTCommunicationEx"        },
	{EPL_ASND_NMTCOMMAND_NMTRESETCONFIGURATIONEX,     "NMTResetConfigurationEx"   },
	{EPL_ASND_NMTCOMMAND_NMTSWRESETEX,                "NMTSwResetEx"              },
	{EPL_ASND_NMTCOMMAND_NMTNETHOSTNAMESET,           "NMTNetHostNameSet"         },
	{EPL_ASND_NMTCOMMAND_NMTFLUSHARPENTRY,            "NMTFlushArpEntry"          },
	{EPL_ASND_NMTCOMMAND_NMTPUBLISHCONFIGUREDNODES,   "NMTPublishConfiguredNodes" },
	{EPL_ASND_NMTCOMMAND_NMTPUBLISHACTIVENODES,       "NMTPublishActiveNodes"     },
	{EPL_ASND_NMTCOMMAND_NMTPUBLISHPREOPERATIONAL1,   "NMTPublishPreOperational1" },
	{EPL_ASND_NMTCOMMAND_NMTPUBLISHPREOPERATIONAL2,   "NMTPublishPreOperational2" },
	{EPL_ASND_NMTCOMMAND_NMTPUBLISHREADYTOOPERATE,    "NMTPublishReadyToOperate"  },
	{EPL_ASND_NMTCOMMAND_NMTPUBLISHOPERATIONAL,       "NMTPublishOperational"     },
	{EPL_ASND_NMTCOMMAND_NMTPUBLISHSTOPPED,           "NMTPublishStopped"         },
	{EPL_ASND_NMTCOMMAND_NMTPUBLISHEMERGENCYNEW,      "NMTPublishEmergencyNew"    },
	{EPL_ASND_NMTCOMMAND_NMTPUBLISHTIME,              "NMTPublishTime"            },
	{EPL_ASND_NMTCOMMAND_NMTINVALIDSERVICE,           "NMTInvalidService"         },
	{0,NULL}
};
static value_string_ext asnd_cid_vals_ext = VALUE_STRING_EXT_INIT(asnd_cid_vals);

/* Maximal Sequence */
#define EPL_MAX_SEQUENCE      0x40
#define EPL_MAX_ADDRESSES     0xF1
/* SCON and RCON values*/
#define EPL_NO_CONNECTION     0x00
#define EPL_INITIALIZATION    0x01
#define EPL_VALID             0x02
#define EPL_ACKREQ            0x03
#define EPL_RETRANSMISSION    0x03
/* MAX Frame offset */
#define EPL_MAX_FRAME_OFFSET  0x64

/* error codes */
#define E_NO_ERROR                          0x0000
#define E_NMT_NO_IDENT_RES                  0xF001
#define E_NMT_NO_STATUS_RES                 0xF002
#define E_DLL_BAD_PHYS_MODE                 0x8161
#define E_DLL_COLLISION                     0x8162
#define E_DLL_COLLISION_TH                  0x8163
#define E_DLL_CRC_TH                        0x8164
#define E_DLL_LOSS_OF_LINK                  0x8165
#define E_DLL_MAC_BUFFER                    0x8166
#define E_DLL_ADDRESS_CONFLICT              0x8201
#define E_DLL_MULTIPLE_MN                   0x8202
#define E_PDO_SHORT_RX                      0x8210
#define E_PDO_MAP_VERS                      0x8211
#define E_NMT_ASND_MTU_DIF                  0x8212
#define E_NMT_ASND_MTU_LIM                  0x8213
#define E_NMT_ASND_TX_LIM                   0x8214
#define E_NMT_CYCLE_LEN                     0x8231
#define E_DLL_CYCLE_EXCEED                  0x8232
#define E_DLL_CYCLE_EXCEED_TH               0x8233
#define E_NMT_IDLE_LIM                      0x8234
#define E_DLL_JITTER_TH                     0x8235
#define E_DLL_LATE_PRES_TH                  0x8236
#define E_NMT_PREQ_CN                       0x8237
#define E_NMT_PREQ_LIM                      0x8238
#define E_NMT_PRES_CN                       0x8239
#define E_NMT_PRES_RX_LIM                   0x823A
#define E_NMT_PRES_TX_LIM                   0x823B
#define E_DLL_INVALID_FORMAT                0x8241
#define E_DLL_LOSS_PREQ_TH                  0x8242
#define E_DLL_LOSS_PRES_TH                  0x8243
#define E_DLL_LOSS_SOA_TH                   0x8244
#define E_DLL_LOSS_SOC_TH                   0x8245
#define E_NMT_BA1                           0x8410
#define E_NMT_BA1_NO_MN_SUPPORT             0x8411
#define E_NMT_BPO1                          0x8420
#define E_NMT_BPO1_GET_IDENT                0x8421
#define E_NMT_BPO1_DEVICE_TYPE              0x8422
#define E_NMT_BPO1_VENDOR_ID                0x8423
#define E_NMT_BPO1_PRODUCT_CODE             0x8424
#define E_NMT_BPO1_REVISION_NO              0x8425
#define E_NMT_BPO1_SERIAL_NO                0x8426
#define E_NMT_BPO1_CF_VERIFY                0x8428
#define E_NMT_BPO2                          0x8430
#define E_NMT_BRO                           0x8440
#define E_NMT_WRONG_STATE                   0x8480

static const value_string errorcode_vals[] = {
	{ E_NO_ERROR,               "E_NO_ERROR" },
	{ E_DLL_BAD_PHYS_MODE,      "E_DLL_BAD_PHYS_MODE" },
	{ E_DLL_COLLISION,          "E_DLL_COLLISION" },
	{ E_DLL_COLLISION_TH,       "E_DLL_COLLISION_TH" },
	{ E_DLL_CRC_TH,             "E_DLL_CRC_TH" },
	{ E_DLL_LOSS_OF_LINK,       "E_DLL_LOSS_OF_LINK" },
	{ E_DLL_MAC_BUFFER,         "E_DLL_MAC_BUFFER" },
	{ E_DLL_ADDRESS_CONFLICT,   "E_DLL_ADDRESS_CONFLICT" },
	{ E_DLL_MULTIPLE_MN,        "E_DLL_MULTIPLE_MN" },
	{ E_PDO_SHORT_RX,           "E_PDO_SHORT_RX" },
	{ E_PDO_MAP_VERS,           "E_PDO_MAP_VERS" },
	{ E_NMT_ASND_MTU_DIF,       "E_NMT_ASND_MTU_DIF" },
	{ E_NMT_ASND_MTU_LIM,       "E_NMT_ASND_MTU_LIM" },
	{ E_NMT_ASND_TX_LIM,        "E_NMT_ASND_TX_LIM" },
	{ E_NMT_CYCLE_LEN,          "E_NMT_CYCLE_LEN" },
	{ E_DLL_CYCLE_EXCEED,       "E_DLL_CYCLE_EXCEED" },
	{ E_DLL_CYCLE_EXCEED_TH,    "E_DLL_CYCLE_EXCEED_TH" },
	{ E_NMT_IDLE_LIM,           "E_NMT_IDLE_LIM" },
	{ E_DLL_JITTER_TH,          "E_DLL_JITTER_TH" },
	{ E_DLL_LATE_PRES_TH,       "E_DLL_LATE_PRES_TH" },
	{ E_NMT_PREQ_CN,            "E_NMT_PREQ_CN" },
	{ E_NMT_PREQ_LIM,           "E_NMT_PREQ_LIM" },
	{ E_NMT_PRES_CN,            "E_NMT_PRES_CN" },
	{ E_NMT_PRES_RX_LIM,        "E_NMT_PRES_RX_LIM" },
	{ E_NMT_PRES_TX_LIM,        "E_NMT_PRES_TX_LIM" },
	{ E_DLL_INVALID_FORMAT,     "E_DLL_INVALID_FORMAT" },
	{ E_DLL_LOSS_PREQ_TH,       "E_DLL_LOSS_PREQ_TH" },
	{ E_DLL_LOSS_PRES_TH,       "E_DLL_LOSS_PRES_TH" },
	{ E_DLL_LOSS_SOA_TH,        "E_DLL_LOSS_SOA_TH" },
	{ E_DLL_LOSS_SOC_TH,        "E_DLL_LOSS_SOC_TH" },
	{ E_NMT_BA1,                "E_NMT_BA1" },
	{ E_NMT_BA1_NO_MN_SUPPORT,  "E_NMT_BA1_NO_MN_SUPPORT" },
	{ E_NMT_BPO1,               "E_NMT_BPO1" },
	{ E_NMT_BPO1_GET_IDENT,     "E_NMT_BPO1_GET_IDENT" },
	{ E_NMT_BPO1_DEVICE_TYPE,   "E_NMT_BPO1_DEVICE_TYPE" },
	{ E_NMT_BPO1_VENDOR_ID,     "E_NMT_BPO1_VENDOR_ID" },
	{ E_NMT_BPO1_PRODUCT_CODE,  "E_NMT_BPO1_PRODUCT_CODE" },
	{ E_NMT_BPO1_REVISION_NO,   "E_NMT_BPO1_REVISION_NO" },
	{ E_NMT_BPO1_SERIAL_NO,     "E_NMT_BPO1_SERIAL_NO" },
	{ E_NMT_BPO1_CF_VERIFY,     "E_NMT_BPO1_CF_VERIFY" },
	{ E_NMT_BPO2,               "E_NMT_BPO2" },
	{ E_NMT_BRO,                "E_NMT_BRO" },
	{ E_NMT_WRONG_STATE,        "E_NMT_WRONG_STATE" },
	{ E_NMT_NO_IDENT_RES,       "E_NMT_NO_IDENT_RES" },
	{ E_NMT_NO_STATUS_RES,      "E_NMT_NO_STATUS_RES" },
	{0,NULL}
};

static value_string_ext errorcode_vals_ext = VALUE_STRING_EXT_INIT(errorcode_vals);

/* duplication table key */
typedef struct {
	guint8 src;
	guint8 dest;
	guint8 seq_send;
	guint8 seq_recv;
} duplication_key;

/* duplication table value */
typedef struct {
	guint32 frame;
} duplication_data;

static guint32 ct = 0;
static guint32 count = 0;

typedef struct _epl_sdo_reassembly
{
	guint32 frame[EPL_MAX_SEQUENCE][EPL_MAX_SEQUENCE];
} epl_sdo_reassembly;

static struct _epl_segmentation{
	guint8 src;
	guint8 dest;
	guint8 recv;
	guint8 send;
} epl_segmentation;

static epl_sdo_reassembly epl_asnd_sdo_reassembly_write;
static epl_sdo_reassembly epl_asnd_sdo_reassembly_read;
static gboolean first_read = TRUE;
static gboolean first_write = TRUE;

/* Priority values for EPL message type "ASnd", "", "", field PR */
#define EPL_PR_GENERICREQUEST   0x03
#define EPL_PR_NMTREQUEST       0x07

static const value_string epl_pr_vals[] = {
	{0,                       "lowest"},
	{1,                       "lower"},
	{2,                       "below generic"},
	{EPL_PR_GENERICREQUEST,   "GenericRequest"},
	{4,                       "above generic"},
	{5,                       "higher"},
	{6,                       "below NMTRequest"},
	{EPL_PR_NMTREQUEST,       "NMTRequest"},
	{0,NULL}
};

/* NMT State values (for CN)*/
#define EPL_NMT_GS_OFF                  0x00
#define EPL_NMT_GS_INITIALIZING         0x19
#define EPL_NMT_GS_RESET_APPLICATION    0x29
#define EPL_NMT_GS_RESET_COMMUNICATION  0x39
#define EPL_NMT_CS_NOT_ACTIVE           0x1C
#define EPL_NMT_CS_PRE_OPERATIONAL_1    0x1D
#define EPL_NMT_CS_PRE_OPERATIONAL_2    0x5D
#define EPL_NMT_CS_READY_TO_OPERATE     0x6D
#define EPL_NMT_CS_OPERATIONAL          0xFD
#define EPL_NMT_CS_STOPPED              0x4D
#define EPL_NMT_CS_BASIC_ETHERNET       0x1E

static const value_string epl_nmt_cs_vals[] = {
	{EPL_NMT_GS_OFF,                  "NMT_GS_OFF"                },
	{EPL_NMT_GS_INITIALIZING,         "NMT_GS_INITIALIZING"       },
	{EPL_NMT_GS_RESET_APPLICATION,    "NMT_GS_RESET_APPLICATION"  },
	{EPL_NMT_GS_RESET_COMMUNICATION,  "NMT_GS_RESET_COMMUNICATION"},
	{EPL_NMT_CS_NOT_ACTIVE,           "NMT_CS_NOT_ACTIVE"         },
	{EPL_NMT_CS_PRE_OPERATIONAL_1,    "NMT_CS_PRE_OPERATIONAL_1"  },
	{EPL_NMT_CS_PRE_OPERATIONAL_2,    "NMT_CS_PRE_OPERATIONAL_2"  },
	{EPL_NMT_CS_READY_TO_OPERATE,     "NMT_CS_READY_TO_OPERATE"   },
	{EPL_NMT_CS_OPERATIONAL,          "NMT_CS_OPERATIONAL"        },
	{EPL_NMT_CS_STOPPED,              "NMT_CS_STOPPED"            },
	{EPL_NMT_CS_BASIC_ETHERNET,       "NMT_CS_BASIC_ETHERNET"     },
	{0,NULL}
};

/* NMT State values (for MN)*/
#define EPL_NMT_GS_OFF                  0x00
#define EPL_NMT_GS_INITIALIZING         0x19
#define EPL_NMT_GS_RESET_APPLICATION    0x29
#define EPL_NMT_GS_RESET_COMMUNICATION  0x39
#define EPL_NMT_MS_NOT_ACTIVE           0x1C
#define EPL_NMT_MS_PRE_OPERATIONAL_1    0x1D
#define EPL_NMT_MS_PRE_OPERATIONAL_2    0x5D
#define EPL_NMT_MS_READY_TO_OPERATE     0x6D
#define EPL_NMT_MS_OPERATIONAL          0xFD
#define EPL_NMT_MS_BASIC_ETHERNET       0x1E

static const value_string epl_nmt_ms_vals[] = {
	{EPL_NMT_GS_OFF,                  "NMT_GS_OFF"                },
	{EPL_NMT_GS_INITIALIZING,         "NMT_GS_INITIALIZING"       },
	{EPL_NMT_GS_RESET_APPLICATION,    "NMT_GS_RESET_APPLICATION"  },
	{EPL_NMT_GS_RESET_COMMUNICATION,  "NMT_GS_RESET_COMMUNICATION"},
	{EPL_NMT_MS_NOT_ACTIVE,           "NMT_MS_NOT_ACTIVE"         },
	{EPL_NMT_MS_PRE_OPERATIONAL_1,    "NMT_MS_PRE_OPERATIONAL_1"  },
	{EPL_NMT_MS_PRE_OPERATIONAL_2,    "NMT_MS_PRE_OPERATIONAL_2"  },
	{EPL_NMT_MS_READY_TO_OPERATE,     "NMT_MS_READY_TO_OPERATE"   },
	{EPL_NMT_MS_OPERATIONAL,          "NMT_MS_OPERATIONAL"        },
	{EPL_NMT_MS_BASIC_ETHERNET,       "NMT_MS_BASIC_ETHERNET"     },
	{0,NULL}
};

/* EPL Device Profiles according to CANopen */
#define EPL_PROFILE_NO              0
#define EPL_PROFILE_GENERIC_IO      401
#define EPL_PROFILE_DRIVE           402
#define EPL_PROFILE_HMI             403
#define EPL_PROFILE_MEASURING       404
#define EPL_PROFILE_PLC             405
#define EPL_PROFILE_ENCODER         406

static const value_string epl_device_profiles[] = {
	{EPL_PROFILE_NO,         "No Standard Device"},
	{EPL_PROFILE_GENERIC_IO, "Generic I/O module"},
	{EPL_PROFILE_DRIVE,      "Drive and motion control"},
	{EPL_PROFILE_HMI,        "Human Machine Interface"},
	{EPL_PROFILE_MEASURING,  "Measuring device"},
	{EPL_PROFILE_PLC,        "IEC 61131-3 PLC"},
	{EPL_PROFILE_ENCODER,    "Encoder"},
	{0,NULL}
};


/* SDO SequenceLayer */
#define EPL_ASND_SDO_SEQ_RECEIVE_SEQUENCE_NUMBER_OFFSET        4
#define EPL_ASND_SDO_SEQ_RECEIVE_CON_OFFSET                    4

#define EPL_ASND_SDO_SEQ_SEND_SEQUENCE_NUMBER_OFFSET           5
#define EPL_ASND_SDO_SEQ_SEND_CON_OFFSET                       5

#define EPL_ASND_SDO_SEQ_RECEIVE_CON_NO_CONNECTION          0x00
#define EPL_ASND_SDO_SEQ_RECEIVE_CON_INITIALIZATION         0x01
#define EPL_ASND_SDO_SEQ_RECEIVE_CON_CONNECTION_VALID       0x02
#define EPL_ASND_SDO_SEQ_RECEIVE_CON_ERROR_RESPONSE         0x03
#define EPL_ASND_SDO_SEQ_CON_MASK                           0x03
#define EPL_ASND_SDO_SEQ_MASK                               0x02

static const value_string epl_sdo_receive_con_vals[] = {
	{EPL_ASND_SDO_SEQ_RECEIVE_CON_NO_CONNECTION,      "No connection"                          },
	{EPL_ASND_SDO_SEQ_RECEIVE_CON_INITIALIZATION,     "Initialization"                         },
	{EPL_ASND_SDO_SEQ_RECEIVE_CON_CONNECTION_VALID,   "Connection valid"                       },
	{EPL_ASND_SDO_SEQ_RECEIVE_CON_ERROR_RESPONSE,     "Error Response (retransmission request)"},
	{0,NULL}
};

#define EPL_ASND_SDO_SEQ_SEND_CON_NO_CONNECTION             0x00
#define EPL_ASND_SDO_SEQ_SEND_CON_INITIALIZATION            0x01
#define EPL_ASND_SDO_SEQ_SEND_CON_CONNECTION_VALID          0x02
#define EPL_ASND_SDO_SEQ_SEND_CON_ERROR_VALID_ACK_REQ       0x03

static const value_string epl_sdo_init_abbr_vals[] = {
	{EPL_ASND_SDO_SEQ_RECEIVE_CON_NO_CONNECTION,      "n" },
	{EPL_ASND_SDO_SEQ_RECEIVE_CON_INITIALIZATION,     "i" },
	{EPL_ASND_SDO_SEQ_RECEIVE_CON_CONNECTION_VALID,   "c" },
	{EPL_ASND_SDO_SEQ_RECEIVE_CON_ERROR_RESPONSE,     "e" },
	{0,NULL}
};

static const value_string epl_sdo_send_con_vals[] = {
	{EPL_ASND_SDO_SEQ_SEND_CON_NO_CONNECTION,         "No connection"                             },
	{EPL_ASND_SDO_SEQ_SEND_CON_INITIALIZATION,        "Initialization"                            },
	{EPL_ASND_SDO_SEQ_SEND_CON_CONNECTION_VALID,      "Connection valid"                          },
	{EPL_ASND_SDO_SEQ_SEND_CON_ERROR_VALID_ACK_REQ,   "Connection valid with acknowledge request" },
	{0,NULL}
};

#define EPL_SDO_INIT_REQUEST    ((EPL_NO_CONNECTION << 8) | EPL_INITIALIZATION)
#define EPL_SDO_INIT_ACK        ((EPL_INITIALIZATION << 8) | EPL_INITIALIZATION)
#define EPL_SDO_INIT_RESPONSE   ((EPL_INITIALIZATION << 8) | EPL_VALID)
#define EPL_SDO_VALID           ((EPL_VALID << 8) | EPL_VALID)
#define EPL_SDO_RETRANSMISSION  ((EPL_RETRANSMISSION << 8) | EPL_VALID)
#define EPL_SDO_ACKREQ          ((EPL_VALID << 8) | EPL_ACKREQ)
#define EPL_SDO_CLOSE           ((EPL_NO_CONNECTION << 8) | EPL_NO_CONNECTION)

static const value_string epl_sdo_init_con_vals[] = {
	{EPL_SDO_INIT_REQUEST,         "InitReq"        },
	{EPL_SDO_INIT_ACK,             "InitAck"        },
	{EPL_SDO_INIT_RESPONSE,        "InitResp"       },
	{EPL_SDO_VALID,                "Valid"          },
	{EPL_SDO_RETRANSMISSION,       "Retrans"        },
	{EPL_SDO_ACKREQ,               "AckReq"         },
	{EPL_SDO_CLOSE,                "Close"          },
	{0,NULL}
};


/* SDO Command Layer Protocol */
#define EPL_ASND_SDO_CMD_ABORT_FILTER                    0x40
#define EPL_ASND_SDO_CMD_SEGMENTATION_FILTER             0x30
#define EPL_ASND_SDO_CMD_RESPONSE_FILTER                 0x80

#define EPL_ASND_SDO_CMD_RESPONSE_RESPONSE                  0
#define EPL_ASND_SDO_CMD_RESPONSE_REQUEST                   1

#define EPL_ASND_SDO_CMD_ABORT_TRANSFER_OK                  0
#define EPL_ASND_SDO_CMD_ABORT_ABORT_TRANSFER               1

#define EPL_ASND_SDO_CMD_SEGMENTATION_EPEDITED_TRANSFER     0
#define EPL_ASND_SDO_CMD_SEGMENTATION_INITIATE_TRANSFER     1
#define EPL_ASND_SDO_CMD_SEGMENTATION_SEGMENT               2
#define EPL_ASND_SDO_CMD_SEGMENTATION_TRANSFER_COMPLETE     3

#define EPL_ASND_SDO_COMMAND_NOT_IN_LIST                        0x00
#define EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX                     0x01
#define EPL_ASND_SDO_COMMAND_READ_BY_INDEX                      0x02
#define EPL_ASND_SDO_COMMAND_WRITE_ALL_BY_INDEX                 0x03
#define EPL_ASND_SDO_COMMAND_READ_ALL_BY_INDEX                  0x04
#define EPL_ASND_SDO_COMMAND_WRITE_BY_NAME                      0x05
#define EPL_ASND_SDO_COMMAND_READ_BY_NAME                       0x06
#define EPL_ASND_SDO_COMMAND_FILE_WRITE                         0x20
#define EPL_ASND_SDO_COMMAND_FILE_READ                          0x21
#define EPL_ASND_SDO_COMMAND_WRITE_MULTIPLE_PARAMETER_BY_INDEX  0x31
#define EPL_ASND_SDO_COMMAND_READ_MULTIPLE_PARAMETER_BY_INDEX   0x32
#define EPL_ASND_SDO_COMMAND_MAXIMUM_SEGMENT_SIZE               0x70
#define EPL_ASND_SDO_COMMAND_LINK_NAME_TO_INDEX                 0x71

/* OD indexes */
#define EPL_SOD_CYLE_LEN        0x1006
#define EPL_SOD_PDO_RX_COMM     0x1400
#define EPL_SOD_PDO_RX_MAPP     0x1600
#define EPL_SOD_PDO_TX_COMM     0x1800
#define EPL_SOD_PDO_TX_MAPP     0x1A00
#define EPL_SDO_SERVER_CONT     0x1200
#define EPL_SDO_CLIENT_CONT     0x1280
#define EPL_SOD_ERR_HISTORY     0x1003
#define EPL_SOD_STORE_PARAM     0x1010
#define EPL_SOD_RESTORE_PARAM   0x1011
#define EPL_SOD_HEARTBEAT_TMN   0x1016
#define EPL_SOD_IDENTITY_OBJECT 0x1018
#define EPL_SOD_VERIFY_CONF     0x1020
#define EPL_SOD_INT_GRP         0x1030
#define EPL_SOD_RLATENCY_DIFF   0x1050
#define EPL_SOD_TELEG_Count     0x1101
#define EPL_SOD_ERR_STAT        0x1102
#define EPL_SOD_STORE_DCF_LST   0x1F20
#define EPL_SOD_STORE_CFM_FMT   0x1F21
#define EPL_SOD_STORE_CON_LST   0x1F22
#define EPL_SOD_STORE_DEV_FILE  0x1F23
#define EPL_SOD_STORE_DEV_FMT   0x1F24
#define EPL_SOD_CONF_REQ        0x1F25
#define EPL_SOD_CONF_DATE       0x1F26
#define EPL_SOD_CONF_TIME       0x1F27
#define EPL_SOD_CONF_ID         0x1F28
#define EPL_SOD_DL_PROG_DATA    0x1F50
#define EPL_SOD_DL_PROG_CTRL    0x1F51
#define EPL_SOD_LOC_SW          0x1F52
#define EPL_SOD_MN_SW_DATE      0x1F53
#define EPL_SOD_MN_SW_TIME      0x1F54
#define EPL_SOD_PROC_IMG        0x1F70
#define EPL_SOD_NMT_NODE        0x1F81
#define EPL_SOD_DEVICE_TYPE_LST 0x1F84
#define EPL_SOD_VENDORID_LST    0x1F85
#define EPL_SOD_PRODUCTEC_LST   0x1F86
#define EPL_SOD_REVISION_NO_LST 0x1F87
#define EPL_SOD_SERIAL_NO_LST   0x1F88
#define EPL_SOD_BOOT_TIME       0x1F89
#define EPL_SOD_CYCLE_TIME      0x1F8A
#define EPL_SOD_PREQ_PAYLOAD    0x1F8B
#define EPL_SOD_PRES_PAYLOAD    0x1F8D
#define EPL_SOD_NODE_STATE      0x1F8E
#define EPL_SOD_NODE_EXP_STATE  0x1F8F
#define EPL_SOD_CNRES_TMOUT     0x1F92
#define EPL_SOD_MULT_CYCL       0x1F9B
#define EPL_SOD_ISO_SLOT_ASSIGN 0x1F9C
#define EPL_SOD_NAT_TABLE       0x1D00
#define EPL_SOD_IP_ADD_TABLE    0x1E40
#define EPL_SOD_ROUTING_TABLE   0x1E90
#define EPL_SOD_ACL_IN_TABLE    0x1ED0
#define EPL_SOD_ACL_OUT_TABLE   0x1EE0
#define EPL_SOD_CYLE_LEN        0x1006
#define EPL_NMT_DEVICE_TYPE     0x1000
#define EPL_ERR_ERROR_REGISTER  0x1001
#define EPL_MANUFACT_DEV_NAME   0x1008
#define EPL_MANUFACT_HW_VERS    0x1009
#define EPL_MANUFACT_SW_VERS    0x100A
#define EPL_STORE_DEV_FILE      0x1021
#define EPL_STORE_DEV_FORMAT    0x1022
#define EPL_INT_GROUP           0x1300
#define EPL_INT_INDEX           0x1301
#define EPL_INT_DESC            0x1302
#define EPL_VERSION             0x1F83
#define EPL_CN_ETH_TIMEOUT      0x1F99
#define EPL_HOST_NAME           0x1F9A
#define EPL_CN_LINK_CUM         0x1C10
#define EPL_CN_JITTER           0x1C13
#define EPL_LOSS_OF_FRAME       0x1C14

static const range_string sod_cmd_str[] = {
	{EPL_SOD_PDO_RX_COMM,   0x14FF,   "0x1400"},
	{EPL_SOD_PDO_RX_MAPP,   0x16FF,   "0x1600"},
	{EPL_SOD_PDO_TX_COMM,   0x18FF,   "0x1800"},
	{EPL_SOD_PDO_TX_MAPP,   0x1AFF,   "0x1A00"},
	{EPL_SDO_SERVER_CONT,   0x1279,   "0x1200"},
	{EPL_SDO_CLIENT_CONT,   0x12FF,   "0x1280"},
	{EPL_SOD_NAT_TABLE,     0x1DFF,   "0x1D00"},
	{EPL_SOD_IP_ADD_TABLE,  0x1E49,   "0x1E40"},
	{EPL_SOD_ROUTING_TABLE, 0x1ECF,   "0x1E90"},
	{EPL_SOD_ACL_IN_TABLE,  0x1EDF,   "0x1ED0"},
	{EPL_SOD_ACL_OUT_TABLE, 0x1EEF,   "0x1EE0"},
	{0,0,NULL}
};

static const value_string sod_cmd_str_val[] = {
	{EPL_SOD_PDO_RX_COMM,   "0x1400"},
	{EPL_SOD_PDO_RX_MAPP,   "0x1600"},
	{EPL_SOD_PDO_TX_COMM,   "0x1800"},
	{EPL_SOD_PDO_TX_MAPP,   "0x1A00"},
	{EPL_SDO_SERVER_CONT,   "0x1200"},
	{EPL_SDO_CLIENT_CONT,   "0x1280"},
	{EPL_SOD_NAT_TABLE,     "0x1D00"},
	{EPL_SOD_IP_ADD_TABLE,  "0x1E40"},
	{EPL_SOD_ROUTING_TABLE, "0x1E90"},
	{EPL_SOD_ACL_IN_TABLE,  "0x1ED0"},
	{EPL_SOD_ACL_OUT_TABLE, "0x1EE0"},
	{0,NULL}
};

static const value_string sod_cmd_sub_str_val[] = {
	{EPL_SOD_ERR_HISTORY,    "0x1003"},
	{EPL_SOD_HEARTBEAT_TMN,  "0x1016"},
	{EPL_SOD_STORE_DCF_LST,  "0x1F20"},
	{EPL_SOD_STORE_CFM_FMT,  "0x1F21"},
	{EPL_SOD_STORE_CON_LST,  "0x1F22"},
	{EPL_SOD_STORE_DEV_FILE, "0x1F23"},
	{EPL_SOD_STORE_DEV_FMT,  "0x1F24"},
	{EPL_SOD_CONF_REQ,       "0x1F25"},
	{EPL_SOD_CONF_DATE,      "0x1F26"},
	{EPL_SOD_CONF_TIME,      "0x1F27"},
	{EPL_SOD_CONF_ID,        "0x1F28"},
	{EPL_SOD_DL_PROG_DATA,   "0x1F50"},
	{EPL_SOD_DL_PROG_CTRL,   "0x1F51"},
	{EPL_SOD_MN_SW_DATE,     "0x1F53"},
	{EPL_SOD_MN_SW_TIME,     "0x1F54"},
	{EPL_SOD_NMT_NODE,       "0x1F81"},
	{EPL_SOD_DEVICE_TYPE_LST,"0x1F84"},
	{EPL_SOD_VENDORID_LST,   "0x1F85"},
	{EPL_SOD_PRODUCTEC_LST,  "0x1F86"},
	{EPL_SOD_REVISION_NO_LST,"0x1F87"},
	{EPL_SOD_SERIAL_NO_LST,  "0x1F88"},
	{EPL_SOD_PREQ_PAYLOAD,   "0x1F8B"},
	{EPL_SOD_PRES_PAYLOAD,   "0x1F8D"},
	{EPL_SOD_NODE_STATE,     "0x1F8E"},
	{EPL_SOD_NODE_EXP_STATE, "0x1F8F"},
	{EPL_SOD_CNRES_TMOUT,    "0x1F92"},
	{EPL_SOD_MULT_CYCL,      "0x1F9B"},
	{EPL_SOD_ISO_SLOT_ASSIGN,"0x1F9C"},
	{0,NULL}
};

static value_string_ext sod_cmd_sub_str = VALUE_STRING_EXT_INIT(sod_cmd_sub_str_val);

static const value_string sod_cmd_str_no_sub[] = {
	{EPL_NMT_DEVICE_TYPE,    "0x1000"},
	{EPL_ERR_ERROR_REGISTER, "0x1001"},
	{EPL_SOD_CYLE_LEN,       "0x1006"},
	{EPL_MANUFACT_DEV_NAME,  "0x1008"},
	{EPL_MANUFACT_HW_VERS,   "0x1009"},
	{EPL_MANUFACT_SW_VERS,   "0x100A"},
	{EPL_STORE_DEV_FILE,     "0x1021"},
	{EPL_STORE_DEV_FORMAT,   "0x1022"},
	{EPL_INT_GROUP,          "0x1300"},
	{EPL_INT_INDEX,          "0x1301"},
	{EPL_INT_DESC,           "0x1302"},
	{EPL_CN_LINK_CUM,        "0x1C10"},
	{EPL_CN_JITTER,          "0x1C13"},
	{EPL_LOSS_OF_FRAME,      "0x1C14"},
	{EPL_VERSION,            "0x1F83"},
	{EPL_CN_ETH_TIMEOUT,     "0x1F99"},
	{EPL_HOST_NAME,          "0x1F9A"},
	{0,NULL}
};

static value_string_ext sod_cmd_no_sub = VALUE_STRING_EXT_INIT(sod_cmd_str_no_sub);

static const value_string sod_idx_names[] = {
	/* SDO directory names */
	{0x10000000, "NMT_DeviceType_U32"},
	{0x10010000, "ERR_ErrorRegister_U8"},
	{0x10030000, "ERR_History_ADOM"},
	{0x10030001, "ErrorEntry_DOM"},
	{0x10060000, "NMT_CycleLen_U32"},
	{0x10080000, "NMT_ManufactDevName_VS"},
	{0x10090000, "NMT_ManufactHwVers_VS"},
	{0x100A0000, "NMT_ManufactSwVers_VS"},
	{0x10100000, "NMT_StoreParam_REC"},
	{0x10100001, "AllParam_U32"},
	{0x10100002, "CommunicationParam_U32"},
	{0x10100003, "ApplicationParam_U32"},
	{0x10100004, "ManufacturerParam_XXh_U32"},

	{0x10110000, "NMT_RestoreDefParam_REC"},
	{0x10110001, "AllParam_U32"},
	{0x10110002, "CommunicationParam_U32"},
	{0x10110003, "ApplicationParam_U32"},
	{0x10110004, "ManufacturerParam_XXh_U32"},

	{0x10160000, "NMT_ConsumerHeartbeatTime_AU32"},
	{0x10160001, "HeartbeatDescription"},

	{0x10180000, "NMT_IdentityObject_REC" },
	{0x10180001, "VendorId_U32" },
	{0x10180002, "ProductCode_U32" },
	{0x10180003, "RevisionNo_U32" },
	{0x10180004, "SerialNo_U32" },

	{0x10200000, "CFM_VerifyConfiguration_REC"},
	{0x10200001, "ConfDate_U32"},
	{0x10200002, "ConfTime_U32"},
	{0x10200003, "ConfId_U32"},
	{0x10200004, "VerifyConfInvalid_BOOL"},

	{0x10210000, "CFM_StoreDevDescrFile_DOM"},
	{0x10220000, "CFM_StoreDevDescrFormat_U16"},

	{0x10300000, "NMT_InterfaceGroup_XX_REC"},
	{0x10300001, "InterfaceIndex_U16"},
	{0x10300002, "InterfaceDescription_VSTR"},
	{0x10300003, "InterfaceType_U8"},
	{0x10300004, "InterfaceMtu_U16"},
	{0x10300005, "InterfacePhysAddress_OSTR"},
	{0x10300006, "InterfaceName_VSTR"},
	{0x10300007, "InterfaceOperStatus_U8"},
	{0x10300008, "InterfaceAdminState_U8"},
	{0x10300009, "Valid_BOOL"},

	{0x10500000, "NMT_RelativeLatencyDiff_AU32"},
	{0x10500000, "RelativeLatencyDiff"},

	{0x11010000, "DIA_NMTTelegrCount_REC"},
	{0x11010001, "IsochrCyc_U32"},
	{0x11010002, "IsochrRx_U32"},
	{0x11010003, "IsochrTx_U32"},
	{0x11010004, "AsyncRx_U32"},
	{0x11010005, "AsyncTx_U32"},
	{0x11010006, "SdoRx_U32"},
	{0x11010007, "SdoTx_U32"},
	{0x11010008, "Status_U32"},

	{0x11020000, "DIA_ERRStatistics_REC"},
	{0x11020001, "HistoryEntryWrite_U32"},
	{0x11020002, "EmergencyQueueWrite_U32"},
	{0x11020003, "EmergencyQueueOverflow_U32"},
	{0x11020004, "StatusEntryChanged_U32"},
	{0x11020005, "StaticErrorBitFieldChanged_U32"},
	{0x11020006, "ExceptionResetEdgePos_U32"},
	{0x11020007, "ExceptionNewEdge_U32"},

	{0x12000000, "SDO_ServerContainerParam"},
	{0x12000001, "ClientNodeID_U8"},
	{0x12000002, "ServerNodeID_U8"},
	{0x12000003, "ContainerLen_U8"},
	{0x12000004, "HistorySize_U8"},

	{0x12800000, "SDO_ClientContainerParam"},
	{0x12800001, "ClientNodeID_U8"},
	{0x12800002, "ServerNodeID_U8"},
	{0x12800003, "ContainerLen_U8"},
	{0x12800004, "HistorySize_U8"},
	{0x12800005, "Reserved"},

	{0x13000000, "SDO_SequLayerTimeout_U32"},
	{0x13010000, "SDO_CmdLayerTimeout_U32"},
	{0x13020000, "SDO_SequLayerNoAck_U32"},

	{0x14000000, "PDO_RxCommParam"},
	{0x14000001, "NodeID_U8"},
	{0x14000002, "MappingVersion_U8"},

	{0x16000000, "PDO_RxMappParam"},
	{0x16000001, "ObjectMapping"},

	{0x18000000, "PDO_TxCommParam"},
	{0x18000001, "NodeID_U8"},
	{0x18000002, "MappingVersion"},

	{0x1A000000, "PDO_TxMappParam"},
	{0x1A000001, "ObjectMapping"},

	{0x1C0A0000, "DLL_CNCollision_REC"},
	{0x1C0A0001, "CumulativeCnt_U32"},
	{0x1C0A0002, "ThresholdCnt_U32"},
	{0x1C0A0003, "Threshold_U32"},

	{0x1C0B0000, "DLL_CNLossSoC_REC"},
	{0x1C0B0001, "CumulativeCnt_U32"},
	{0x1C0B0002, "ThresholdCnt_U32"},
	{0x1C0B0003, "Threshold_U32"},

	{0x1C0C0000, "DLL_CNLossSoA_REC"},
	{0x1C0C0001, "CumulativeCnt_U32"},
	{0x1C0C0002, "ThresholdCnt_U32"},
	{0x1C0C0003, "Threshold_U32"},

	{0x1C0D0000, "DLL_CNLossPReq_REC"},
	{0x1C0D0001, "CumulativeCnt_U32"},
	{0x1C0D0002, "ThresholdCnt_U32"},
	{0x1C0D0003, "Threshold_U32"},

	{0x1C0E0000, "DLL_CNSoCJitter_REC"},
	{0x1C0E0001, "CumulativeCnt_U32"},
	{0x1C0E0002, "ThresholdCnt_U32"},
	{0x1C0E0003, "Threshold_U32"},

	{0x1C0F0000, "DLL_CNCRCError_REC"},
	{0x1C0F0001, "CumulativeCnt_U32"},
	{0x1C0F0002, "ThresholdCnt_U32"},
	{0x1C0F0003, "Threshold_U32"},

	{0x1C100000, "DLL_CNLossOfLinkCum_U32"},
	{0x1C130000, "DLL_CNSoCJitterRange_U32"},
	{0x1C140000, "DLL_LossOfFrameTolerance_U32"},

	{0x1D000000, "RT1_NatTable"},
	{0x1D000001, "EplIpAddr_IPAD"},
	{0x1D000002, "ExtIpAddr_IPAD"},
	{0x1D000003, "Mask_IPAD"},
	{0x1D000004, "Type_U8"},

	{0x1E400000, "NWL_IpAddrTable"},
	{0x1E400001, "IfIndex_U16"},
	{0x1E400002, "Addr_IPAD"},
	{0x1E400003, "NetMask_IPAD"},
	{0x1E400004, "ReasmMaxSize_U16"},
	{0x1E400005, "DefaultGateway_IPAD"},
	{0x1E4A0000, "NWL_IpGroup_REC"},
	{0x1E4A0001, "Forwarding_BOOL"},
	{0x1E4A0002, "DefaultTTL_U16"},
	{0x1E4A0003, "ForwardDatagrams_U32"},
	{0x1E800000, "RT1_EplRouter_REC"},
	{0x1E800001, "EnableNat_BOOL"},
	{0x1E800002, "EnablePacketFiltering_BOOL"},
	{0x1E810000, "RT1_SecurityGroup_REC"},
	{0x1E810001, "FwdTablePolicy_U8"},
	{0x1E810002, "InTablePolicy_U8"},
	{0x1E810003, "OutTablePolicy_U8"},

	{0x1E900000, "RT1_IpRoutingTable"},
	{0x1E900001, "IpForwardDest_IPAD"},
	{0x1E900002, "IpForwardMask_IPAD"},
	{0x1E900003, "IpForwardNextHop_IPAD"},
	{0x1E900004, "IpForwardType_U8"},
	{0x1E900005, "IpForwardAge_U32"},
	{0x1E900006, "IpForwardItfIndex_U16"},
	{0x1E900007, "IpForwardMetric1_S32"},

	{0x1ED00000, "RT1_AclInTable"},
	{0x1ED00001, "SrcIp_IPAD"},
	{0x1ED00002, "SrcMask_IPAD"},
	{0x1ED00003, "DstIp_IPAD"},
	{0x1ED00004, "DstMask_IPAD"},
	{0x1ED00005, "Protocol_U8"},
	{0x1ED00006, "SrcPort_U16"},
	{0x1ED00007, "DstPort_U16"},
	{0x1ED00008, "SrcMac_MAC"},
	{0x1ED00009, "Target_U8"},

	{0x1EE00000, "RT1_AclOutTable"},
	{0x1EE00001, "SrcIp_IPAD"},
	{0x1EE00002, "SrcMask_IPAD"},
	{0x1EE00003, "DstIp_IPAD"},
	{0x1EE00004, "DstMask_IPAD"},
	{0x1EE00005, "Protocol_U8"},
	{0x1EE00006, "SrcPort_U16"},
	{0x1EE00007, "DstPort_U16"},
	{0x1EE00008, "SrcMac_MAC"},
	{0x1EE00009, "Target_U8"},

	{0x1F200000, "CFM_StoreDcfList_ADOM"},
	{0x1F200001, "CNDcf"},
	{0x1F210000, "CFM_DcfStorageFormatList_AU8"},
	{0x1F210001, "CNDcfFormat"},
	{0x1F220000, "CFM_ConciseDcfList_ADOM"},
	{0x1F220001, "CNConciseDcfData"},
	{0x1F230000, "CFM_StoreDevDescrFileList_ADOM"},
	{0x1F230001, "CNDevDescrFile"},
	{0x1F240000, "CFM_DevDescrFileFormatList_AU8"},
	{0x1F240001, "CNDevDescrFileFormat"},
	{0x1F250000, "CFM_ConfCNRequest_AU32"},
	{0x1F250001, "CNConfigurationRequest"},
	{0x1F260000, "CFM_ExpConfDateList_AU32"},
	{0x1F260001, "CNConfigurationDate"},
	{0x1F270000, "CFM_ExpConfTimeList_AU32"},
	{0x1F270001, "CNConfigurationTime"},
	{0x1F280000, "CFM_ExpConfIdList_AU32"},
	{0x1F280001, "CNConfigurationId"},

	{0x1F500000, "PDL_DownloadProgData_ADOM"},
	{0x1F500001, "Program"},
	{0x1F510000, "PDL_ProgCtrl_AU8"},
	{0x1F510001, "ProgCtrl"},
	{0x1F520000, "PDL_LocVerApplSw_REC"},
	{0x1F520001, "ApplSwDate_U32"},
	{0x1F520002, "ApplSwTime_U32"},
	{0x1F530000, "PDL_MnExpAppSwDateList_AU32"},
	{0x1F530001, "AppSwDate"},
	{0x1F540000, "PDL_MnExpAppSwTimeList_AU32"},
	{0x1F540001, "AppSwTime"},

	{0x1F700000, "INP_ProcessImage_REC"},
	{0x1F700001, "SelectedRange_U32"},
	{0x1F700002, "ProcessImageDomain_DOM"},

	{0x1F800000, "NMT_StartUp_U32"},
	{0x1F810000, "NMT_NodeAssignment_AU32"},
	{0x1F810001, "NodeAssignment"},
	{0x1F820000, "NMT_FeatureFlags_U32"},
	{0x1F830000, "NMT_EPLVersion_U8"},
	{0x1F840000, "NMT_MNDeviceTypeIdList_AU32"},
	{0x1F840001, "CNDeviceTypeId"},
	{0x1F850000, "NMT_MNVendorIdList_AU32"},
	{0x1F850001, "CNVendorId"},
	{0x1F860000, "NMT_MNProductCodeList_AU32"},
	{0x1F860001, "CNProductCode"},
	{0x1F870000, "NMT_MNRevisionNoList_AU32"},
	{0x1F870001, "CNRevisionNo"},
	{0x1F880000, "NMT_MNSerialNoList_AU32"},
	{0x1F880001, "CNSerialNo"},

	{0x1F890000, "NMT_BootTime_REC"},
	{0x1F890001, "MNWaitNotAct_U32"},
	{0x1F890002, "MNTimeoutPreOp1_U32"},
	{0x1F890003, "MNWaitPreOp1_U32"},
	{0x1F890004, "MNTimeoutPreOp2_U32"},
	{0x1F890005, "MNTimeoutReadyToOp_U32"},
	{0x1F890006, "MNIdentificationTimeout_U32"},
	{0x1F890007, "MNSoftwareTimeout_U32"},
	{0x1F890008, "MNConfigurationTimeout_U32"},
	{0x1F890009, "MNStartCNTimeout_U32"},
	{0x1F89000A, "MNSwitchOverPriority_U32"},
	{0x1F89000B, "MNSwitchOverDelay_U32"},
	{0x1F89000C, "MNSwitchOverCycleDivider_U32"},

	{0x1F8A0000, "NMT_MNCycleTiming_REC"},
	{0x1F8A0001, "WaitSoCPReq_U32"},
	{0x1F8A0002, "AsyncSlotTimeout_U32"},
	{0x1F8A0003, "ASndMaxNumber"},

	{0x1F8B0000, "NMT_MNPReqPayloadLimitList_AU16"},
	{0x1F8B0001, "CNPReqPayload"},
	{0x1F8C0000, "NMT_CurrNMTState_U8"},
	{0x1F8D0000, "NMT_PResPayloadLimitList_AU16"},
	{0x1F8D0001, "PResPayloadLimit"},
	{0x1F8E0000, "NMT_MNNodeCurrState_AU8"},
	{0x1F8E0001, "CurrState"},
	{0x1F8F0000, "NMT_MNNodeExpState_AU8"},
	{0x1F8F0001, "ExpState"},

	{0x1F920000, "NMT_MNCNPResTimeout_AU32"},
	{0x1F920001, "CNResTimeout"},

	{0x1F930000, "NMT_EPLNodeID_REC"},
	{0x1F930001, "NodeID_U8"},
	{0x1F930002, "NodeIDByHW_BOOL"},
	{0x1F930003, "SWNodeID_U8"},

	{0x1F980000, "NMT_CycleTiming_REC"},
	{0x1F980001, "IsochrTxMaxPayload_U16"},
	{0x1F980002, "IsochrRxMaxPayload_U16"},
	{0x1F980003, "PResMaxLatency_U32"},
	{0x1F980004, "PReqActPayloadLimit_U16"},
	{0x1F980005, "PResActPayloadLimit_U16"},
	{0x1F980006, "ASndMaxLatency_U32"},
	{0x1F980007, "MultiplCycleCnt_U8"},
	{0x1F980008, "AsyncMTU_U16"},
	{0x1F980009, "Prescaler_U16"},
	{0x1F98000A, "PResMode_U8"},
	{0x1F98000B, "PResTimeFirst_U32"},
	{0x1F98000C, "PResTimeSecond_U32"},
	{0x1F98000D, "SyncMNDelayFirst_U32"},
	{0x1F98000E, "SyncMNDelaySecond_U32"},

	{0x1F990000, "NMT_CNBasicEthernetTimeout_U32"},
	{0x1F9A0000, "NMT_HostName_VSTR"},
	{0x1F9B0000, "NMT_MultiplCycleAssign_AU8"},
	{0x1F9B0001, "CycleNo"},
	{0x1F9C0000, "NMT_IsochrSlotAssign_AU8"},
	{0x1F9C0001, "NodeId"},
	{0x1F9E0000, "NMT_ResetCmd_U8"},
	{0x1F9F0000, "NMT_RequestCmd_REC"},
	{0x1F9F0001, "Release_BOOL"},
	{0x1F9F0002, "CmdID_U8"},
	{0x1F9F0003, "CmdTarget_U8"},
	{0x1F9F0004, "CmdData_DOM"},

	{0,NULL}
};

static value_string_ext sod_index_names = VALUE_STRING_EXT_INIT(sod_idx_names);

/* SDO - Abort Transfer */
static const value_string sdo_cmd_abort_code[] = {
	{0x05030000, "reserved" },
	{0x05040000, "SDO protocol timed out." },
	{0x05040001, "Client/server Command ID not valid or unknown." },
	{0x05040002, "Invalid block size." },
	{0x05040003, "Invalid sequence number." },
	{0x05040004, "reserved" },
	{0x05040005, "Out of memory." },
	{0x06010000, "Unsupported access to an object." },
	{0x06010001, "Attempt to read a write-only object." },
	{0x06010002, "Attempt to write a read-only object." },
	{0x06020000, "Object does not exist in the object dictionary." },
	{0x06040041, "Object cannot be mapped to the PDO." },
	{0x06040042, "The number and length of the objects to be mapped would exceed PDO length." },
	{0x06040043, "General parameter incompatibility." },
	{0x06040047, "General internal incompatibility in the device." },
	{0x06060000, "Access failed due to a hardware error." },
	{0x06070010, "Data type does not match, length of service parameter does not match." },
	{0x06070012, "Data type does not match, length of service parameter too high." },
	{0x06070013, "Data type does not match, length of service parameter too low." },
	{0x06090011, "Sub-index does not exist." },
	{0x06090030, "Value range of parameter exceeded (only for write access)." },
	{0x06090031, "Value of parameter written too high." },
	{0x06090032, "Value of parameter written too low." },
	{0x06090036, "Maximum value is less then minimum value." },
	{0x08000000, "General error" },
	{0x08000020, "Data cannot be transferred or stored to the application." },
	{0x08000021, "Data cannot be transferred or stored to the application because of local control." },
	{0x08000022, "Data cannot be transferred or stored to the application because of the present device state." },
	{0x08000023, "Object dictionary dynamic generation fails or no object dictionary is present." },
	{0x08000024, "EDS, DCF or Concise DCF Data set empty." },
	{0,NULL}
};
static value_string_ext sdo_cmd_abort_code_ext = VALUE_STRING_EXT_INIT(sdo_cmd_abort_code);

static const value_string epl_sdo_asnd_cmd_response[] = {
	{EPL_ASND_SDO_CMD_RESPONSE_RESPONSE,                    "Request"   },
	{EPL_ASND_SDO_CMD_RESPONSE_REQUEST,                     "Response"  },
	{0,NULL}
};

static const value_string epl_sdo_asnd_cmd_abort[] = {
	{EPL_ASND_SDO_CMD_ABORT_TRANSFER_OK,                    "Transfer OK"    },
	{EPL_ASND_SDO_CMD_ABORT_ABORT_TRANSFER,                 "Abort Transfer" },
	{0,NULL}
};

static const value_string epl_sdo_asnd_cmd_segmentation[] = {
	{EPL_ASND_SDO_CMD_SEGMENTATION_EPEDITED_TRANSFER,       "Expedited Transfer" },
	{EPL_ASND_SDO_CMD_SEGMENTATION_INITIATE_TRANSFER,       "Initiate Transfer"  },
	{EPL_ASND_SDO_CMD_SEGMENTATION_SEGMENT,                 "Segment"            },
	{EPL_ASND_SDO_CMD_SEGMENTATION_TRANSFER_COMPLETE,       "Transfer Complete"  },
	{0,NULL}
};

static const value_string epl_sdo_asnd_cmd_segmentation_abbr[] = {
	{EPL_ASND_SDO_CMD_SEGMENTATION_EPEDITED_TRANSFER,       "EX" },
	{EPL_ASND_SDO_CMD_SEGMENTATION_INITIATE_TRANSFER,       "SI"  },
	{EPL_ASND_SDO_CMD_SEGMENTATION_SEGMENT,                 "ST"            },
	{EPL_ASND_SDO_CMD_SEGMENTATION_TRANSFER_COMPLETE,       "SC"  },
	{0,NULL}
};

static const value_string epl_sdo_asnd_commands[] = {
	{EPL_ASND_SDO_COMMAND_NOT_IN_LIST                      , "Not in List"                       },
	{EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX                   , "Write by Index"                    },
	{EPL_ASND_SDO_COMMAND_READ_BY_INDEX                    , "Read by Index"                     },
	{EPL_ASND_SDO_COMMAND_WRITE_ALL_BY_INDEX               , "Write All by Index"                },
	{EPL_ASND_SDO_COMMAND_READ_ALL_BY_INDEX                , "Read All by Index"                 },
	{EPL_ASND_SDO_COMMAND_WRITE_BY_NAME                    , "Write by Name"                     },
	{EPL_ASND_SDO_COMMAND_READ_BY_NAME                     , "Read by Name"                      },
	{EPL_ASND_SDO_COMMAND_FILE_WRITE                       , "File Write"                        },
	{EPL_ASND_SDO_COMMAND_FILE_READ                        , "File Read"                         },
	{EPL_ASND_SDO_COMMAND_WRITE_MULTIPLE_PARAMETER_BY_INDEX, "Write Multiple Parameter by Index" },
	{EPL_ASND_SDO_COMMAND_READ_MULTIPLE_PARAMETER_BY_INDEX , "Read Multiple Parameter by Index"  },
	{EPL_ASND_SDO_COMMAND_MAXIMUM_SEGMENT_SIZE             , "Maximum Segment Size"              },
	{EPL_ASND_SDO_COMMAND_LINK_NAME_TO_INDEX               , "Link objects only accessible via name to an index/sub-index"},
	{0,NULL}
};

static value_string_ext epl_sdo_asnd_commands_ext = VALUE_STRING_EXT_INIT(epl_sdo_asnd_commands);

static const value_string epl_sdo_asnd_commands_short[] = {
	{EPL_ASND_SDO_COMMAND_NOT_IN_LIST                      , "NotInList"                        },
	{EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX                   , "WriteByIndex"                     },
	{EPL_ASND_SDO_COMMAND_READ_BY_INDEX                    , "ReadByIndex"                      },
	{EPL_ASND_SDO_COMMAND_WRITE_ALL_BY_INDEX               , "WriteAllByIndex"                  },
	{EPL_ASND_SDO_COMMAND_READ_ALL_BY_INDEX                , "ReadAllByIndex"                   },
	{EPL_ASND_SDO_COMMAND_WRITE_BY_NAME                    , "WriteByName"                      },
	{EPL_ASND_SDO_COMMAND_READ_BY_NAME                     , "ReadByName"                       },
	{EPL_ASND_SDO_COMMAND_FILE_WRITE                       , "FileWrite"                        },
	{EPL_ASND_SDO_COMMAND_FILE_READ                        , "FileRead"                         },
	{EPL_ASND_SDO_COMMAND_WRITE_MULTIPLE_PARAMETER_BY_INDEX, "WriteMultipleParam"               },
	{EPL_ASND_SDO_COMMAND_READ_MULTIPLE_PARAMETER_BY_INDEX , "ReadMultipleParam"                },
	{0,NULL}
};


static value_string_ext epl_sdo_asnd_commands_short_ext = VALUE_STRING_EXT_INIT(epl_sdo_asnd_commands_short);


static const gchar* addr_str_cn  = " (Controlled Node)";
static const gchar* addr_str_res = " (reserved)";

struct epl_convo;

static gint dissect_epl_payload(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, gint len, const struct epl_datatype *type, guint8 msgType);
static gint dissect_epl_soc(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset);
static gint dissect_epl_preq(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset);
static gint dissect_epl_pres(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset);
static gint dissect_epl_soa(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset);

static gint dissect_epl_asnd_ires(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset);
static gint dissect_epl_asnd_sres(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset);
static gint dissect_epl_asnd_nmtcmd(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset);
static gint dissect_epl_asnd_nmtreq(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset);
static gint dissect_epl_asnd_nmtdna(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset);
static gint dissect_epl_asnd(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset);
static gint dissect_epl_ainv(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset);

static gint dissect_epl_asnd_sdo(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset);
static gint dissect_epl_asnd_resp(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset);
static gint dissect_epl_sdo_sequence(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset);
static gint dissect_epl_sdo_command(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset);
static gint dissect_epl_sdo_command_write_by_index(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 segmented, gboolean response, guint16 segment_size);
static gint dissect_epl_sdo_command_write_multiple_by_index(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 segmented, gboolean response, guint16 segment_size);
static gint dissect_epl_sdo_command_read_by_index(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 segmented, gboolean response, guint16 segment_size);
static gint dissect_object_mapping(struct profile *profile, wmem_array_t *mappings, proto_tree *epl_tree, tvbuff_t *tvb, guint32 framenum, gint offset, guint16 idx, guint8 subindex);

static const gchar* decode_epl_address(guchar adr);

/* Initialize the protocol and registered fields */
static gint proto_epl            = -1;

static gint hf_epl_mtyp          = -1;
static gint hf_epl_node          = -1;
static gint hf_epl_dest          = -1;
static gint hf_epl_src           = -1;
static gint hf_epl_payload_real  = -1;

static gint hf_epl_soc           = -1;
static gint hf_epl_soc_mc        = -1;
static gint hf_epl_soc_ps        = -1;
static gint hf_epl_soc_nettime   = -1;
static gint hf_epl_soc_relativetime = -1;

static gint hf_epl_preq          = -1;
static gint hf_epl_preq_ms       = -1;
static gint hf_epl_preq_ea       = -1;
static gint hf_epl_preq_rd       = -1;
static gint hf_epl_preq_pdov     = -1;
static gint hf_epl_preq_size     = -1;

static gint hf_epl_pres_stat_ms  = -1;
static gint hf_epl_pres_stat_cs  = -1;
static gint hf_epl_pres          = -1;
static gint hf_epl_pres_ms       = -1;
static gint hf_epl_pres_en       = -1;
static gint hf_epl_pres_rd       = -1;
static gint hf_epl_pres_pr       = -1;
static gint hf_epl_pres_rs       = -1;
static gint hf_epl_pres_pdov     = -1;
static gint hf_epl_pres_size     = -1;

static gint hf_epl_soa_stat_ms   = -1;
static gint hf_epl_soa_stat_cs   = -1;
static gint hf_epl_soa_ea        = -1;
static gint hf_epl_soa_er        = -1;
static gint hf_epl_soa_svid      = -1;
static gint hf_epl_soa_svtg      = -1;
static gint hf_epl_soa_eplv      = -1;

/*SyncRequest*/
static gint hf_epl_soa_sync      = -1;
static gint hf_epl_soa_mac       = -1;
static gint hf_epl_soa_pre_fst   = -1;
static gint hf_epl_soa_pre_sec   = -1;
static gint hf_epl_soa_mnd_fst   = -1;
static gint hf_epl_soa_mnd_sec   = -1;
static gint hf_epl_soa_pre_tm    = -1;
static gint hf_epl_soa_pre_set   = -1;
static gint hf_epl_soa_pre_res   = -1;
static gint hf_epl_soa_mac_end   = -1;
static gint hf_epl_soa_pre_fst_end   = -1;
static gint hf_epl_soa_pre_sec_end   = -1;
static gint hf_epl_soa_mnd_fst_end   = -1;
static gint hf_epl_soa_mnd_sec_end   = -1;
static gint hf_epl_soa_pre_tm_end    = -1;
static gint hf_epl_soa_dna_an_glb    = -1;
static gint hf_epl_soa_dna_an_lcl    = -1;

/*SyncResponse*/
static gint hf_epl_asnd_syncResponse_sync           = -1;
static gint hf_epl_asnd_syncResponse_latency        = -1;
static gint hf_epl_asnd_syncResponse_node           = -1;
static gint hf_epl_asnd_syncResponse_delay          = -1;
static gint hf_epl_asnd_syncResponse_pre_fst        = -1;
static gint hf_epl_asnd_syncResponse_pre_sec        = -1;
static gint hf_epl_asnd_syncResponse_fst_val        = -1;
static gint hf_epl_asnd_syncResponse_sec_val        = -1;
static gint hf_epl_asnd_syncResponse_mode           = -1;

static gint hf_epl_asnd_svid      = -1;
static gint hf_epl_asnd_svtg      = -1;
/* static gint hf_epl_asnd_data     = -1; */

/*IdentResponse*/
static gint hf_epl_asnd_identresponse_en             = -1;
static gint hf_epl_asnd_identresponse_ec             = -1;
static gint hf_epl_asnd_identresponse_pr             = -1;
static gint hf_epl_asnd_identresponse_rs             = -1;
static gint hf_epl_asnd_identresponse_stat_ms        = -1;
static gint hf_epl_asnd_identresponse_stat_cs        = -1;
static gint hf_epl_asnd_identresponse_ever           = -1;
static gint hf_epl_asnd_identresponse_feat           = -1;
static gint hf_epl_asnd_identresponse_feat_bit0      = -1;
static gint hf_epl_asnd_identresponse_feat_bit1      = -1;
static gint hf_epl_asnd_identresponse_feat_bit2      = -1;
static gint hf_epl_asnd_identresponse_feat_bit3      = -1;
static gint hf_epl_asnd_identresponse_feat_bit4      = -1;
static gint hf_epl_asnd_identresponse_feat_bit5      = -1;
static gint hf_epl_asnd_identresponse_feat_bit6      = -1;
static gint hf_epl_asnd_identresponse_feat_bit7      = -1;
static gint hf_epl_asnd_identresponse_feat_bit8      = -1;
static gint hf_epl_asnd_identresponse_feat_bit9      = -1;
static gint hf_epl_asnd_identresponse_feat_bitA      = -1;
static gint hf_epl_asnd_identresponse_feat_bitB      = -1;
static gint hf_epl_asnd_identresponse_feat_bitC      = -1;
static gint hf_epl_asnd_identresponse_feat_bitD      = -1;
static gint hf_epl_asnd_identresponse_feat_bitE      = -1;
static gint hf_epl_asnd_identresponse_feat_bitF      = -1;
static gint hf_epl_asnd_identresponse_feat_bit10     = -1;
static gint hf_epl_asnd_identresponse_feat_bit11     = -1;
static gint hf_epl_asnd_identresponse_feat_bit12     = -1;
static gint hf_epl_asnd_identresponse_feat_bit13     = -1;
static gint hf_epl_asnd_identresponse_feat_bit14     = -1;
static gint hf_epl_asnd_identresponse_mtu            = -1;
static gint hf_epl_asnd_identresponse_pis            = -1;
static gint hf_epl_asnd_identresponse_pos            = -1;
static gint hf_epl_asnd_identresponse_rst            = -1;
static gint hf_epl_asnd_identresponse_dt             = -1;
static gint hf_epl_asnd_identresponse_profile        = -1;
static gint hf_epl_asnd_identresponse_vid            = -1;
static gint hf_epl_asnd_identresponse_productcode    = -1;
static gint hf_epl_asnd_identresponse_rno            = -1;
static gint hf_epl_asnd_identresponse_sno            = -1;
static gint hf_epl_asnd_identresponse_vex1           = -1;
static gint hf_epl_asnd_identresponse_vcd            = -1;
static gint hf_epl_asnd_identresponse_vct            = -1;
static gint hf_epl_asnd_identresponse_ad             = -1;
static gint hf_epl_asnd_identresponse_at             = -1;
static gint hf_epl_asnd_identresponse_ipa            = -1;
static gint hf_epl_asnd_identresponse_snm            = -1;
static gint hf_epl_asnd_identresponse_gtw            = -1;
static gint hf_epl_asnd_identresponse_hn             = -1;
static gint hf_epl_asnd_identresponse_vex2           = -1;

/*StatusResponse*/
static gint hf_epl_asnd_statusresponse_en            = -1;
static gint hf_epl_asnd_statusresponse_ec            = -1;
static gint hf_epl_asnd_statusresponse_pr            = -1;
static gint hf_epl_asnd_statusresponse_rs            = -1;
static gint hf_epl_asnd_statusresponse_stat_ms       = -1;
static gint hf_epl_asnd_statusresponse_stat_cs       = -1;
/* static gint hf_epl_asnd_statusresponse_seb           = -1; */

/*StaticErrorBitField */
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit0 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit1 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit2 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit3 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit4 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit5 = -1;
static gint hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit7 = -1;
static gint hf_epl_asnd_statusresponse_seb_devicespecific_err        = -1;

/*List of Errors/Events*/
/* static gint hf_epl_asnd_statusresponse_el                    = -1; */
/* static gint hf_epl_asnd_statusresponse_el_entry              = -1; */
static gint hf_epl_asnd_statusresponse_el_entry_type         = -1;
static gint hf_epl_asnd_statusresponse_el_entry_type_profile = -1;
static gint hf_epl_asnd_statusresponse_el_entry_type_mode    = -1;
static gint hf_epl_asnd_statusresponse_el_entry_type_bit14   = -1;
static gint hf_epl_asnd_statusresponse_el_entry_type_bit15   = -1;
static gint hf_epl_asnd_statusresponse_el_entry_code         = -1;
static gint hf_epl_asnd_statusresponse_el_entry_time         = -1;
static gint hf_epl_asnd_statusresponse_el_entry_add          = -1;

/*NMTRequest*/
static gint hf_epl_asnd_nmtrequest_rcid                      = -1;
static gint hf_epl_asnd_nmtrequest_rct                       = -1;
static gint hf_epl_asnd_nmtrequest_rcd                       = -1;

/*NMTCommand*/
static gint hf_epl_asnd_nmtcommand_cid                       = -1;
static gint hf_epl_asnd_nmtcommand_cdat                      = -1;
static gint hf_epl_asnd_nmtcommand_resetnode_reason           = -1;
/*static gint hf_epl_asnd_nmtcommand_nmtnetparameterset_mtu    = -1;*/
static gint hf_epl_asnd_nmtcommand_nmtnethostnameset_hn      = -1;
static gint hf_epl_asnd_nmtcommand_nmtflusharpentry_nid      = -1;
static gint hf_epl_asnd_nmtcommand_nmtpublishtime_dt         = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna                    = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_flags              = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_ltv                = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_hpm                = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_nnn                = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_mac                = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_cnn                = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_currmac            = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_hubenmsk           = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_currnn             = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_newnn              = -1;
static gint hf_epl_asnd_nmtcommand_nmtdna_leasetime          = -1;


/*Asynchronuous SDO Sequence Layer*/
static gint hf_epl_asnd_sdo_seq                              = -1;
static gint hf_epl_asnd_sdo_seq_receive_sequence_number      = -1;
static gint hf_epl_asnd_sdo_seq_receive_con                  = -1;
static gint hf_epl_asnd_sdo_seq_send_sequence_number         = -1;
static gint hf_epl_asnd_sdo_seq_send_con                     = -1;

/*Asynchronuous SDO Command Layer*/
static gint hf_epl_asnd_sdo_cmd                              = -1;
static gint hf_epl_asnd_sdo_cmd_transaction_id               = -1;
static gint hf_epl_asnd_sdo_cmd_response                     = -1;
static gint hf_epl_asnd_sdo_cmd_abort                        = -1;
static gint hf_epl_asnd_sdo_cmd_sub_abort                    = -1;
static gint hf_epl_asnd_sdo_cmd_segmentation                 = -1;
static gint hf_epl_asnd_sdo_cmd_command_id                   = -1;
static gint hf_epl_asnd_sdo_cmd_segment_size                 = -1;

static gint hf_epl_asnd_sdo_cmd_data_size                    = -1;
static gint hf_epl_asnd_sdo_cmd_data_padding                 = -1;
static gint hf_epl_asnd_sdo_cmd_data_index                   = -1;
static gint hf_epl_asnd_sdo_cmd_data_subindex                = -1;
static gint hf_epl_asnd_sdo_cmd_data_mapping                 = -1;
static gint hf_epl_asnd_sdo_cmd_data_mapping_index           = -1;
static gint hf_epl_asnd_sdo_cmd_data_mapping_subindex        = -1;
static gint hf_epl_asnd_sdo_cmd_data_mapping_offset          = -1;
static gint hf_epl_asnd_sdo_cmd_data_mapping_length          = -1;
/*static gint hf_epl_asnd_sdo_cmd_data_response      = -1;*/

static gint hf_epl_asnd_sdo_cmd_reassembled                  = -1;
static gint hf_epl_fragments                                 = -1;
static gint hf_epl_fragment                                  = -1;
static gint hf_epl_fragment_overlap                          = -1;
static gint hf_epl_fragment_overlap_conflicts                = -1;
static gint hf_epl_fragment_multiple_tails                   = -1;
static gint hf_epl_fragment_too_long_fragment                = -1;
static gint hf_epl_fragment_error                            = -1;
static gint hf_epl_fragment_count                            = -1;
static gint hf_epl_reassembled_in                            = -1;
static gint hf_epl_reassembled_length                        = -1;
static gint hf_epl_reassembled_data                          = -1;

static gint hf_epl_asnd_identresponse_profile_path = -1;

/* EPL OD Data Types */
static gint hf_epl_pdo                = -1;
static gint hf_epl_pdo_index          = -1;
static gint hf_epl_pdo_subindex       = -1;
static gint hf_epl_pdo_meta_info      = -1;

static gint hf_epl_od_boolean         = -1;
static gint hf_epl_od_integer8        = -1;
static gint hf_epl_od_integer16       = -1;
static gint hf_epl_od_integer24       = -1;
static gint hf_epl_od_integer32       = -1;
static gint hf_epl_od_integer40       = -1;
static gint hf_epl_od_integer48       = -1;
static gint hf_epl_od_integer56       = -1;
static gint hf_epl_od_integer64       = -1;
static gint hf_epl_od_real32          = -1;
static gint hf_epl_od_real64          = -1;
static gint hf_epl_od_visible_string  = -1;
static gint hf_epl_od_octet_string    = -1;
static gint hf_epl_od_unicode_string  = -1;
/*static gint hf_epl_od_time_of_day     = -1;*/
/*static gint hf_epl_od_time_difference = -1;*/
static gint hf_epl_od_nettime         = -1;

static gint hf_epl_od_domain     = -1;
static gint hf_epl_od_mac        = -1;
static gint hf_epl_od_ipv4       = -1;

#define EPL_PDO_TYPE_COUNT 8
static gint hf_epl_od_unsigned[EPL_PDO_TYPE_COUNT]
	= {  -1, -1, -1, -1, -1, -1, -1, -1 };
#define SIZE_TO_UNSIGNED_HF(size) ((0 < (size) && (size) <= EPL_PDO_TYPE_COUNT) \
		? &hf_epl_od_unsigned[(size) - 1] : NULL)

static const struct epl_datatype {
	const char *name;
	gint *hf;
	guint encoding;
	guint8 len;
} epl_datatype[] = {
	{ "Boolean",        &hf_epl_od_boolean,   ENC_LITTLE_ENDIAN , 1},
	/* integer types */
	{ "Integer8",       &hf_epl_od_integer8 , ENC_LITTLE_ENDIAN, 1},
	{ "Integer16",      &hf_epl_od_integer16, ENC_LITTLE_ENDIAN, 2},
	{ "Integer24",      &hf_epl_od_integer24, ENC_LITTLE_ENDIAN, 3},
	{ "Integer32",      &hf_epl_od_integer32, ENC_LITTLE_ENDIAN, 4},
	{ "Integer40",      &hf_epl_od_integer40, ENC_LITTLE_ENDIAN, 5},
	{ "Integer48",      &hf_epl_od_integer48, ENC_LITTLE_ENDIAN, 6},
	{ "Integer56",      &hf_epl_od_integer56, ENC_LITTLE_ENDIAN, 7},
	{ "Integer64",      &hf_epl_od_integer64, ENC_LITTLE_ENDIAN, 8},

	{ "Unsigned8",  SIZE_TO_UNSIGNED_HF(1), ENC_LITTLE_ENDIAN, 1},
	{ "Unsigned16", SIZE_TO_UNSIGNED_HF(2), ENC_LITTLE_ENDIAN, 2},
	{ "Unsigned24", SIZE_TO_UNSIGNED_HF(3), ENC_LITTLE_ENDIAN, 3},
	{ "Unsigned32", SIZE_TO_UNSIGNED_HF(4), ENC_LITTLE_ENDIAN, 4},
	{ "Unsigned40", SIZE_TO_UNSIGNED_HF(5), ENC_LITTLE_ENDIAN, 5},
	{ "Unsigned48", SIZE_TO_UNSIGNED_HF(6), ENC_LITTLE_ENDIAN, 6},
	{ "Unsigned56", SIZE_TO_UNSIGNED_HF(7), ENC_LITTLE_ENDIAN, 7},
	{ "Unsigned64", SIZE_TO_UNSIGNED_HF(8), ENC_LITTLE_ENDIAN, 8},

	/* non-integer types */


	{ "Real32",         &hf_epl_od_real32,    ENC_LITTLE_ENDIAN, 4},
	{ "Real64",         &hf_epl_od_real64,    ENC_LITTLE_ENDIAN, 8},
	{ "Visible_String", &hf_epl_od_visible_string,  ENC_ASCII, 0},
	{ "Octet_String",   &hf_epl_od_octet_string,    ENC_NA, 0},
	{ "Unicode_String", &hf_epl_od_unicode_string,  ENC_UCS_2, 0},
	/*{ "Time_of_Day",    &hf_epl_od_time_of_day,     ENC_NA},*/
	/*{ "Time_Diff",      &hf_epl_od_time_difference, ENC_NA },*/
	{ "NETTIME",        &hf_epl_od_nettime, ENC_TIME_TIMESPEC, 8},

	/*{ "Domain",         &hf_epl_od_domain, ENC_NA },*/
	{ "MAC_ADDRESS",    &hf_epl_od_mac,    ENC_BIG_ENDIAN, 6},
	{ "IP_ADDRESS",     &hf_epl_od_ipv4,   ENC_BIG_ENDIAN, 4},

	{ NULL, NULL }
};


const struct
epl_datatype *epl_type_to_hf(const char *name)
{
	const struct epl_datatype *entry;
	for (entry = epl_datatype; entry->name; entry++)
	{
		if (strcmp(name, entry->name) == 0)
			return entry;
	}
	return NULL;
}


static gint ett_epl_fragment                                 = -1;
static gint ett_epl_fragments                                = -1;

static const fragment_items epl_frag_items = {
	/* Fragment subtrees */
	&ett_epl_fragment,
	&ett_epl_fragments,
	/* Fragment fields */
	&hf_epl_fragments,
	&hf_epl_fragment,
	&hf_epl_fragment_overlap,
	&hf_epl_fragment_overlap_conflicts,
	&hf_epl_fragment_multiple_tails,
	&hf_epl_fragment_too_long_fragment,
	&hf_epl_fragment_error,
	&hf_epl_fragment_count,
	/* Reassembled in field */
	&hf_epl_reassembled_in,
	/* Reassembled length field */
	&hf_epl_reassembled_length,
	/* Reassembled data */
	&hf_epl_reassembled_data,
	/* Tag */
	"Message fragments"
};

static gint hf_epl_asnd_sdo_cmd_abort_code                   = -1;
/*static gint hf_epl_asnd_sdo_cmd_abort_flag                   = -1;*/
/*static gint hf_epl_asnd_sdo_cmd_segmentation_flag            = -1;*/
/*static gint hf_epl_asnd_sdo_cmd_cmd_valid_test               = -1;*/

/*static gint hf_epl_asnd_sdo_actual_command_id                = -1;*/

/*static gint hf_epl_asnd_sdo_actual_segment_size              = -1;*/
/*static gint hf_epl_asnd_sdo_actual_payload_size_read         = -1;*/

/* Initialize the subtree pointers */
static gint ett_epl                 = -1;
static gint ett_epl_soc             = -1;
static gint ett_epl_preq            = -1;
static gint ett_epl_pres            = -1;
static gint ett_epl_feat            = -1;
static gint ett_epl_seb             = -1;
static gint ett_epl_el              = -1;
static gint ett_epl_el_entry        = -1;
static gint ett_epl_el_entry_type   = -1;
static gint ett_epl_sdo_entry_type  = -1;
static gint ett_epl_asnd_nmt_dna    = -1;

static gint ett_epl_sdo                       = -1;
static gint ett_epl_sdo_sequence_layer        = -1;
static gint ett_epl_sdo_command_layer         = -1;
static gint ett_epl_sdo_data                  = -1;
static gint ett_epl_asnd_sdo_cmd_data_mapping = -1;
static gint ett_epl_soa_sync                  = -1;
static gint ett_epl_asnd_sync                 = -1;

static expert_field ei_duplicated_frame       = EI_INIT;
static expert_field ei_recvseq_value          = EI_INIT;
static expert_field ei_sendseq_value          = EI_INIT;
static expert_field ei_recvcon_value          = EI_INIT;
static expert_field ei_sendcon_value          = EI_INIT;
static expert_field ei_real_length_differs    = EI_INIT;

static dissector_handle_t epl_handle;

static gboolean show_cmd_layer_for_duplicated = FALSE;
static gboolean show_pdo_meta_info = FALSE;
static gboolean read_xdc_for_mappings = TRUE;

static gint ett_epl_asnd_sdo_data_reassembled = -1;

static reassembly_table epl_reassembly_table;


gboolean
epl_g_int16_equal(gconstpointer v1, gconstpointer v2)
{
	return *(const guint16*)v1 == *(const guint16*)v2;
}

guint
epl_g_int16_hash(gconstpointer v)
{
	return *(const guint16*)v;
}

gboolean
epl_g_int8_equal(gconstpointer v1, gconstpointer v2)
{
	return *(const guint8*)v1 == *(const guint8*)v2;
}

guint
epl_g_int8_hash(gconstpointer v)
{
	return *(const guint8*)v;
}

static wmem_allocator_t *pdo_mapping_scope;
struct object_mapping {
	struct {
		guint16 idx;
		guint8 subindex;
	} pdo,   /* The PDO to be mapped */
	  param; /* The ObjectMapping OD entry that mapped it */

	guint16 bit_offset;
	guint16 no_of_bits;
	int ett;
	/* info */
	struct {
		guint32 first, last;
	} frame; /* frames for which object_mapping applies */
	struct od_entry *info;
	const char *index_name;
	const char *title;
};

static struct object_mapping *
get_object_mappings(wmem_array_t *arr, guint *len)
{
	*len = wmem_array_get_count(arr);
	return (struct object_mapping*)wmem_array_get_raw(arr);
}
int
object_mapping_cmp(const void *_a, const void *_b)
{
	const struct object_mapping *a = (const struct object_mapping*)_a;
	const struct object_mapping *b = (const struct object_mapping*)_b;

	if (a->bit_offset < b->bit_offset) return -1;
	if (a->bit_offset > b->bit_offset) return +1;
	return 0;
}
gboolean
object_mapping_eq(struct object_mapping *a, struct object_mapping *b)
{
	return a->pdo.idx == b->pdo.idx
	    && a->pdo.subindex == b->pdo.subindex
	    && a->frame.first == b->frame.first
	    && a->param.idx == b->param.idx
	    && a->param.subindex == b->param.subindex;
}
static guint
add_object_mapping(wmem_array_t *arr, struct object_mapping *mapping)
{
	/* let's check if this overwrites an existing mapping */
	guint i, len;
	/* A bit ineffecient (looping backwards would be better), but it's acyclic anyway */
	struct object_mapping *old = get_object_mappings(arr, &len);
	for (i = 0; i < len; i++)
	{
		/* XXX Test this more */
		if (object_mapping_eq(&old[i], mapping))
			return len;

		if (old[i].frame.first < mapping->frame.first
		  && (CHECK_OVERLAP_LENGTH(old[i].bit_offset, old[i].no_of_bits, mapping->bit_offset, mapping->no_of_bits)
		  || (old[i].param.idx == mapping->param.idx && old[i].param.subindex == mapping->param.subindex
		  && CHECK_OVERLAP_ENDS(old[i].frame.first, old[i].frame.last, mapping->frame.first, mapping->frame.last))))
		{
			old[i].frame.last = mapping->frame.first;
		}
	}

	wmem_array_append(arr, mapping, 1);
	wmem_array_sort(arr, object_mapping_cmp);
	return len + 1;
}

static wmem_map_t *epl_profiles_by_device, *epl_profiles_by_nodeid;

static gboolean
profile_del_cb(wmem_allocator_t *pool _U_, wmem_cb_event_t event _U_, void *_profile)
{
	struct profile *profile = (struct profile*)_profile;
	if (profile->parent_map)
		wmem_map_remove(profile->parent_map, profile->data);
	wmem_destroy_allocator(profile->scope);
	return FALSE;
}

static void
profile_del(struct profile *profile)
{
	wmem_unregister_callback(profile->parent_scope, profile->cb_id);
	profile_del_cb(NULL, WMEM_CB_DESTROY_EVENT, profile);
}

static struct profile *
profile_new(wmem_allocator_t *parent_pool)
{
	wmem_allocator_t *pool;
	struct profile *profile;
	
	pool = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);
	profile = wmem_new0(pool, struct profile);
	profile->cb_id = wmem_register_callback(parent_pool, profile_del_cb, profile);

	profile->scope        = pool;
	profile->parent_scope = parent_pool;
	profile->parent_map   = NULL;
	profile->objects      = wmem_map_new(pool, epl_g_int16_hash, epl_g_int16_equal);
	profile->name         = NULL;
	profile->path         = NULL;
	profile->RPDO         = wmem_array_new(pool, sizeof (struct object_mapping));
	profile->TPDO         = wmem_array_new(pool, sizeof (struct object_mapping));
	profile->next         = NULL;

	return profile;
}

struct object *
profile_object_add(struct profile *profile, guint16 idx)
{
	struct object *object = wmem_new0(profile->scope, struct object);

	object->info.idx = idx;

	wmem_map_insert(profile->objects, &object->info.idx, object);
	return object;
}

struct object *
profile_object_lookup_or_add(struct profile *profile, guint16 idx)
{
	struct object *obj = object_lookup(profile, idx);
	return obj ? obj : profile_object_add(profile, idx);
}


gboolean
profile_object_mapping_add(struct profile *profile, guint16 idx, guint8 subindex, guint64 mapping)
{
	wmem_array_t *mappings;
	tvbuff_t *tvb;
	guint64 mapping_le;

	if (!read_xdc_for_mappings)
		return FALSE;

	if(idx == EPL_SOD_PDO_RX_MAPP && subindex >= 0x01 && subindex <= 0xfe)
		mappings = profile->RPDO;
	else if (idx == EPL_SOD_PDO_TX_MAPP && subindex >= 0x01 && subindex <= 0xfe)
		mappings = profile->TPDO;
	else
		return FALSE;

	mapping_le = GUINT64_TO_LE(mapping);
	tvb = tvb_new_real_data((guint8*)&mapping_le, sizeof mapping_le, sizeof mapping_le);

	return dissect_object_mapping(profile, mappings, NULL, tvb, 0, 0, idx, subindex) == sizeof mapping;
}

static struct subobject * subobject_lookup(struct object *obj, guint8 subindex);

gboolean
profile_object_mappings_update(struct profile *profile)
{
	gboolean updated_any = FALSE;
	guint i, len;
	struct object_mapping *mappings;
	wmem_array_t *PDOs[3], **PDO;

	if (!read_xdc_for_mappings)
		return FALSE;


	PDOs[0] = profile->RPDO;
	PDOs[1] = profile->TPDO;
	PDOs[2] = NULL;

	for (PDO = PDOs; *PDO; PDO++)
	{
		len = wmem_array_get_count(*PDO);
		mappings = (struct object_mapping*)wmem_array_get_raw(*PDO);

		for (i = 0; i < len; i++)
		{
			struct object_mapping *map = &mappings[i];
			struct object *mapping_obj;
			struct subobject *mapping_subobj;

			if (!(mapping_obj = object_lookup(profile, map->pdo.idx)))
				continue;
			map->info = &mapping_obj->info;
			map->index_name = map->info->name;
			updated_any = TRUE;
			if (!(mapping_subobj = subobject_lookup(mapping_obj, map->pdo.subindex)))
				continue;
			map->info = &mapping_subobj->info;
		}
	}

	return updated_any;
}


struct epl_convo {
	guint8 CN;

	guint16 DeviceType;
	guint32 ResponseTime;
	guint32 VendorId;
	guint32 ProductCode;


	wmem_array_t *TPDO; /* CN->MN */
	wmem_array_t *RPDO; /* MN->CN */
	struct {
		struct profile *CN, *MN;
	} profiles;

	guint32 last_frame;
	guint8 next_read_req;
	guint8 seq_send;
	
	struct read_req {
		guint16 idx;
		guint8 subindex;

		guint8 sendsequence;

		const char *index_name;
		struct od_entry *info;
	} read_reqs[4];
	/* In lieu of allocating an unknown number of read requests, we'll keep a ring
	 * buff of the 4 most recent ones and when a response comes we add them as packet
	 * data
	 */
};

static struct read_req *
convo_read_req_get(struct epl_convo *convo, packet_info *pinfo, guint8 SendSequenceNumber)
{
	guint i;
	guint32 seq_p_key = (ETHERTYPE_EPL_V2 << 16) | convo->seq_send;
	struct read_req *req = (struct read_req*)p_get_proto_data(wmem_file_scope(), pinfo, proto_epl, seq_p_key);

	if (req)
		return req;

	for (i = 0; i < array_length(convo->read_reqs); i++)
	{
		if(convo->read_reqs[i].sendsequence == SendSequenceNumber)
		{
			req = wmem_new(wmem_file_scope(), struct read_req);
			*req = convo->read_reqs[i];
			p_add_proto_data(wmem_file_scope(), pinfo, proto_epl, seq_p_key, req);
			return req;
		}
	}

	return NULL;
}
static struct read_req *
convo_read_req_set(struct epl_convo *convo, guint8 SendSequenceNumber)
{
	struct read_req *slot = &convo->read_reqs[convo->next_read_req++];
	convo->next_read_req %= array_length(convo->read_reqs);
	slot->sendsequence = SendSequenceNumber;
	return slot;
}


static int
dissect_epl_pdo(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint offset, guint len, guint8 msgType)
{
	wmem_array_t *mapping = msgType == EPL_PRES ? convo->TPDO : convo->RPDO;
	tvbuff_t *payload_tvb;
	guint rem_len, rem_len_bits;
	guint i, maps_count;
	guint off = 0;

	struct object_mapping *mappings = get_object_mappings(mapping, &maps_count);

	rem_len = tvb_captured_length_remaining(tvb, offset);
	payload_tvb = tvb_new_subset_length(tvb, offset, len > rem_len ? rem_len : len);
	rem_len = tvb_captured_length_remaining(payload_tvb, 0);
	rem_len_bits = rem_len * 8;


	for (i = 0; i < maps_count; i++)
	{
		proto_tree *pdo_tree;
		proto_item *psf_item, *ti;
		struct object_mapping *map = &mappings[i];
		guint willbe_offset_bits = map->bit_offset + map->no_of_bits;

		if (!(map->frame.first < pinfo->num && pinfo->num < map->frame.last))
			continue;

		if (willbe_offset_bits > rem_len_bits)
			break;

		psf_item = proto_tree_add_string_format(epl_tree, hf_epl_pdo, payload_tvb, 0, 0, "", "%s", map->title);
		pdo_tree = proto_item_add_subtree(psf_item, map->ett);

		ti = proto_tree_add_uint_format_value(pdo_tree, hf_epl_pdo_index, payload_tvb, 0, 0, map->pdo.idx, "%04X", map->pdo.idx);
		PROTO_ITEM_SET_GENERATED(ti);
		if (map->info)
			proto_item_append_text (ti, " (%s)", map->index_name);

		ti = proto_tree_add_uint_format_value(pdo_tree, hf_epl_pdo_subindex, payload_tvb, 0, 0, map->pdo.subindex, "%02X", map->pdo.subindex);
		PROTO_ITEM_SET_GENERATED(ti);

		if (map->info && map->info->name != map->index_name)
			proto_item_append_text (ti, " (%s)", map->info->name);

		if (show_pdo_meta_info)
		{
			ti = proto_tree_add_string_format(pdo_tree, hf_epl_asnd_identresponse_profile_path, tvb, 0, 0,
					"", "Mapping set by %04X:%02X, Life time: Frame #%u-#%u, Offset: 0x%04x, Length %u bits",
					map->param.idx, map->param.subindex, map->frame.first, map->frame.last, map->bit_offset, map->no_of_bits
					);
			PROTO_ITEM_SET_GENERATED(ti);
		}

		dissect_epl_payload(
				pdo_tree,
				tvb_new_octet_aligned(payload_tvb, map->bit_offset, map->no_of_bits),
				pinfo, 0, map->no_of_bits / 8, map->info ? map->info->type : NULL, msgType
		); 

		off = willbe_offset_bits / 8;
	}

	/* If we don't have more information, resort to data dissector */
	if (tvb_captured_length_remaining(payload_tvb, off))
	{
		return dissect_epl_payload(epl_tree, payload_tvb, pinfo, off, rem_len, NULL, msgType);
	}
	return offset + len;
}

static address convo_mac;

static struct epl_convo *
epl_get_convo(guint32 framenum, guint8 cn_addr)
{
	struct epl_convo *convo;
	conversation_t * epan_convo;
	guint32 last_frame = 0;

	/* I2C port is also single octet wide */
	if ((epan_convo = find_conversation(framenum, &convo_mac, &convo_mac, PT_I2C,
					cn_addr, cn_addr, NO_ADDR_B|NO_PORT_B)))
	{
		/* TODO: use conversation template? */

		last_frame = epan_convo->last_frame;
		if (framenum > epan_convo->last_frame)
			epan_convo->last_frame = framenum;
	} else {
		epan_convo = conversation_new(framenum, &convo_mac, &convo_mac, PT_I2C,
				cn_addr, cn_addr, NO_ADDR2|NO_PORT2);
	}

	convo = (struct epl_convo*)conversation_get_proto_data(epan_convo, proto_epl);

	if (convo == NULL)
	{
		convo = wmem_new0(wmem_file_scope(), struct epl_convo);
		convo->CN = cn_addr;
		convo->TPDO = wmem_array_new(pdo_mapping_scope, sizeof (struct object_mapping));
		convo->RPDO = wmem_array_new(pdo_mapping_scope, sizeof (struct object_mapping));

		convo->profiles.MN = NULL;
		convo->profiles.CN = (struct profile*)wmem_map_lookup(epl_profiles_by_nodeid, &convo->CN);
		convo->seq_send = 0x00;
		conversation_add_proto_data(epan_convo, proto_epl, (void *)convo);
	}
	convo->last_frame = last_frame;

	return convo;
}

static struct epl_convo *
epl_convo_cutoff(struct epl_convo *convo)
{
	conversation_t *old_epan_convo;
	guint32 old_last = convo->last_frame;
	guint32 new_first;

	if (old_last == 0)
		return convo;

	old_epan_convo = find_conversation(old_last, &convo_mac, &convo_mac, PT_I2C,
					convo->CN, convo->CN, NO_ADDR_B|NO_PORT_B);

	new_first = old_epan_convo->last_frame;
	old_epan_convo->last_frame = old_last;
	return epl_get_convo(new_first, convo->CN);
}

gboolean
epl_update_convo_cn_profile(struct epl_convo *convo)
{
	struct profile *candidate; /* Best matching profile */
	if ((candidate = (struct profile*)wmem_map_lookup(epl_profiles_by_device, &convo->DeviceType)))
	{
		struct profile *iter = candidate;
		do {
			if ((iter->VendorId == 0 && convo->ProductCode == 0 && !candidate->VendorId)
			|| (iter->VendorId == convo->VendorId && !candidate->ProductCode)
			|| (iter->VendorId == convo->VendorId &&  iter->ProductCode == convo->ProductCode))
			{
				candidate = iter;
			}

		} while ((iter = iter->next));


		convo->profiles.CN = candidate;
		/* TODO: leaks memory when profile is changed? */
		if (!wmem_array_get_count(convo->RPDO))
		{
			wmem_array_append(convo->RPDO,
				wmem_array_get_raw(candidate->RPDO),
				wmem_array_get_count(candidate->RPDO)
			);
		}
		if (!wmem_array_get_count(convo->TPDO))
		{
			wmem_array_append(convo->TPDO,
				wmem_array_get_raw(candidate->TPDO),
				wmem_array_get_count(candidate->TPDO)
			);
		}
		return TRUE;
	}
	return FALSE;
}

struct object *
object_lookup(struct profile *profile, guint16 idx)
{
	if (profile == NULL)
		return NULL;

	return (struct object*)wmem_map_lookup(profile->objects, &idx);
}

gboolean
subobject_equal(gconstpointer _a, gconstpointer _b)
{
	const struct od_entry *a = &((const struct subobject*)_a)->info;
	const struct od_entry *b = &((const struct subobject*)_b)->info;

	return a->kind == b->kind
	    && a->type == b->type
	    && g_str_equal(a->name, b->name);
}
static struct subobject *
subobject_lookup(struct object *obj, guint8 subindex)
{
	if (!obj || !obj->subindices) return NULL;
	return (struct subobject*)epl_wmem_iarray_find(obj->subindices, subindex);
}

static GHashTable *epl_duplication_table = NULL;

/* epl duplication table hash function */
static guint
epl_duplication_hash(gconstpointer k)
{
	const duplication_key *key = (const duplication_key*)k;
	guint hash;

	hash = ((key->src)<<24) | ((key->dest)<<16)|
		((key->seq_recv)<<8)|(key->seq_send);

	return hash;
}

/* epl duplication table equal function */
static gint
epl_duplication_equal(gconstpointer k1, gconstpointer k2)
{
	const duplication_key *key1 = (const duplication_key*)k1;
	const duplication_key *key2 = (const duplication_key*)k2;
	gint hash;

	hash = (key1->src == key2->src)&&(key1->dest == key2->dest)&&
		(key1->seq_recv == key2->seq_recv)&&(key1->seq_send == key2->seq_send);

	return hash;
}

/* free the permanent key */
static void
free_key(gpointer ptr)
{
	duplication_key *key = (duplication_key *)ptr;

	if(key)
		g_slice_free(duplication_key, key);
}

/* removes the table entries of a specific transfer */
static void
epl_duplication_remove(GHashTable* table, guint8 src, guint8 dest)
{
	GHashTableIter iter;
	gpointer pkey, pvalue;
	duplication_key *key;

	g_hash_table_iter_init(&iter, table);

	while(g_hash_table_iter_next(&iter, &pkey, &pvalue))
	{
		key = (duplication_key *)pkey;

		if((src == key->src) && (dest == key->dest))
		{
			/* remove the key + value from the hash table */
			g_hash_table_iter_remove(&iter);
		}
	}
}

/* insert function */
static void
epl_duplication_insert(GHashTable* table, gpointer ptr, guint32 frame)
{
	duplication_data *data = NULL;
	duplication_key *key = NULL;
	gpointer pkey = NULL;
	gpointer pdata;

	/* check if the values are stored */
	if(g_hash_table_lookup_extended(table,ptr,&pkey,&pdata))
	{
		data = (duplication_data *)pdata;
		data->frame = frame;
		g_hash_table_insert(table, pkey, data);
	}
	/* insert the data struct into the table */
	else
	{
		key = (duplication_key *)wmem_memdup(wmem_file_scope(), ptr,sizeof(duplication_key));
		/* create memory */
		data = (duplication_data *)wmem_alloc0(wmem_file_scope(), sizeof(duplication_data));
		data->frame = frame;
		g_hash_table_insert(table,(gpointer)key, data);
	}
}

/* create a key*/
static gpointer
epl_duplication_key(guint8 src, guint8 dest, guint8 seq_recv, guint8 seq_send)
{
	duplication_key *key = g_slice_new(duplication_key);

	key->src = src;
	key->dest = dest;
	key->seq_recv = seq_recv;
	key->seq_send = seq_send;

	return (gpointer)key;
}

/* get the saved data */
static guint32
epl_duplication_get(GHashTable* table, gpointer ptr)
{
	duplication_data *data = NULL;
	gpointer *pkey = NULL;
	gpointer pdata;

	if(g_hash_table_lookup_extended(table,ptr,pkey,&pdata))
	{
		data = (duplication_data *)pdata;
		if(data->frame == 0x00)
			return 0x00;
	}
	if(data != NULL)
		return data->frame;
	else
		return 0x00;
}

static void
setup_dissector(void)
{
	/* init duplication hash table */
	epl_duplication_table = g_hash_table_new(epl_duplication_hash, epl_duplication_equal);

	/* create memory block for upload/download */
	memset(&epl_asnd_sdo_reassembly_write, 0, sizeof(epl_sdo_reassembly));
	memset(&epl_asnd_sdo_reassembly_read, 0, sizeof(epl_sdo_reassembly));
	/* create reassembly table */
	reassembly_table_init(&epl_reassembly_table, &addresses_reassembly_table_functions);
	/* free object mappings in one swoop */
	pdo_mapping_scope = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);
}

static void
cleanup_dissector(void)
{
	wmem_destroy_allocator(pdo_mapping_scope);
	pdo_mapping_scope = NULL;
	reassembly_table_destroy(&epl_reassembly_table);
	/*g_hash_free(epl_duplication_table);*/
	count = 0;
	ct = 0;
	first_read = TRUE;
	first_write = TRUE;
}

/* preference whether or not display the SoC flags in info column */
gboolean show_soc_flags = FALSE;

/* Define the tap for epl */
/*static gint epl_tap = -1;*/

static guint16
epl_get_sequence_nr(packet_info *pinfo)
{
	guint16 seqnum = 0x00;
	gpointer data = NULL;

	if ( ( data = p_get_proto_data ( wmem_file_scope(), pinfo, proto_epl, ETHERTYPE_EPL_V2 ) ) == NULL )
		p_add_proto_data ( wmem_file_scope(), pinfo, proto_epl, ETHERTYPE_EPL_V2, GUINT_TO_POINTER((guint)seqnum) );
	else
		seqnum = GPOINTER_TO_UINT(data);

	return seqnum;
}

static void
epl_set_sequence_nr(packet_info *pinfo, guint16 seqnum)
{
	if ( p_get_proto_data ( wmem_file_scope(), pinfo, proto_epl, ETHERTYPE_EPL_V2 ) != NULL )
		p_remove_proto_data( wmem_file_scope(), pinfo, proto_epl, ETHERTYPE_EPL_V2 );

	p_add_proto_data ( wmem_file_scope(), pinfo, proto_epl, ETHERTYPE_EPL_V2, GUINT_TO_POINTER((guint)seqnum) );
}

static void
elp_version( gchar *result, guint32 version )
{
	g_snprintf( result, ITEM_LABEL_LENGTH, "%d.%d", hi_nibble(version), lo_nibble(version));
}
/* Code to actually dissect the packets */
static int
dissect_eplpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean udpencap)
{
	struct epl_convo *convo;
	guint8 epl_mtyp, epl_src, epl_dest;
	const  gchar *src_str, *dest_str;
	/* static epl_info_t mi; */
	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *epl_tree = NULL, *epl_src_item, *epl_dest_item;
	gint offset = 0, size = 0;
	heur_dtbl_entry_t *hdtbl_entry;
	guint8 cn_addr = 0;

	if (tvb_reported_length(tvb) < 3)
	{
		/* Not enough data for an EPL header; don't try to interpret it */
		return FALSE;
	}

	/* Make entries in Protocol column and Info column on summary display */
	if (!udpencap)
	{
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "POWERLINK");
	}
	else
	{
		/* guess that this is an EPL frame encapsulated into an UDP datagram */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "POWERLINK/UDP");
	}

	/* Get message type */
	epl_mtyp = tvb_get_guint8(tvb, EPL_MTYP_OFFSET) & 0x7F;

	/*
	* In case the packet is a protocol encoded in the basic EPL transport stream,
	* give that protocol a chance to make a heuristic dissection, before we continue
	* to dissect it as a normal EPL packet.
	*/
	if (dissector_try_heuristic(heur_epl_subdissector_list, tvb, pinfo, tree, &hdtbl_entry, &epl_mtyp))
		return TRUE;

	/* tap */
	/*  mi.epl_mtyp = epl_mtyp;
	tap_queue_packet(epl_tap, pinfo, &mi);
	*/

	/* Get Destination */
	epl_dest = tvb_get_guint8(tvb, EPL_DEST_OFFSET);
	epl_segmentation.dest = epl_dest;
	dest_str = decode_epl_address(epl_dest);

	/* Get Source */
	epl_src = tvb_get_guint8(tvb, EPL_SRC_OFFSET);
	epl_segmentation.src = epl_src;
	src_str = decode_epl_address(epl_src);

	/* Get conversation */
	cn_addr = src_str  == addr_str_cn ? epl_src
		: dest_str == addr_str_cn ? epl_dest
		: 0;
	convo = epl_get_convo(pinfo->num, cn_addr);





	col_clear(pinfo->cinfo, COL_INFO);

	/* Choose the right string for "Info" column (message type) */
	switch (epl_mtyp)
	{
		case EPL_SOC:
			col_add_fstr(pinfo->cinfo, COL_INFO, "%3d->%3d SoC    ", epl_src, epl_dest);
			break;

		case EPL_PREQ:
			col_add_fstr(pinfo->cinfo, COL_INFO, "%3d->%3d  PReq ", epl_src, epl_dest);
			break;

		case EPL_PRES:
			col_add_fstr(pinfo->cinfo, COL_INFO, "%3d->%3d  PRes ", epl_src, epl_dest);
			break;

		case EPL_SOA:
			col_add_fstr(pinfo->cinfo, COL_INFO, "%3d->%3d  SoA  ", epl_src, epl_dest);
			break;

		case EPL_ASND:
			if (udpencap)
			{
				col_set_str(pinfo->cinfo, COL_INFO,  "          ASnd ");
			}
			else
			{
				col_add_fstr(pinfo->cinfo, COL_INFO, "%3d->%3d  ASnd ", epl_src, epl_dest);
			}
			break;

		case EPL_AINV:
			if (udpencap)
			{
				col_set_str(pinfo->cinfo, COL_INFO,  "          AInv ");
			}
			else
			{
				col_add_fstr(pinfo->cinfo, COL_INFO, "%3d->%3d  AInv ", epl_src, epl_dest);
			}
			break;

		case EPL_AMNI:
			col_add_fstr(pinfo->cinfo, COL_INFO, "%3d->%3d AMNI   ", epl_src, epl_dest);
			break;

		default:    /* no valid EPL packet */
			return FALSE;
	}

	if (tree)
	{
		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_epl, tvb, 0, -1, ENC_NA);
		epl_tree = proto_item_add_subtree(ti, ett_epl);

		proto_tree_add_item(epl_tree,
			hf_epl_mtyp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	offset += 1;

	if (tree && !udpencap)
	{
		epl_dest_item = proto_tree_add_item(epl_tree, hf_epl_node, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(epl_dest_item);
		epl_dest_item = proto_tree_add_item(epl_tree, hf_epl_dest, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text (epl_dest_item, "%s", dest_str);
		offset += 1;

		epl_src_item = proto_tree_add_item(epl_tree, hf_epl_node, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		PROTO_ITEM_SET_HIDDEN(epl_src_item);
		epl_src_item = proto_tree_add_item(epl_tree, hf_epl_src, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text (epl_src_item, "%s", src_str);
		offset += 1;
	}
	else
	{
		offset += 2;
	}

	/* The rest of the EPL dissector depends on the message type  */
	switch (epl_mtyp)
	{
		case EPL_SOC:
			offset = dissect_epl_soc(epl_tree, tvb, pinfo, offset);
			break;

		case EPL_PREQ:
			offset = dissect_epl_preq(convo, epl_tree, tvb, pinfo, offset);
			break;

		case EPL_PRES:
			offset = dissect_epl_pres(convo, epl_tree, tvb, pinfo, epl_src, offset);
			break;

		case EPL_SOA:
			offset = dissect_epl_soa(epl_tree, tvb, pinfo, epl_src, offset);
			break;

		case EPL_ASND:
			offset = dissect_epl_asnd(convo, epl_tree, tvb, pinfo, epl_src, offset);
			break;

		case EPL_AINV:
			offset = dissect_epl_ainv(convo, epl_tree, tvb, pinfo, epl_src, offset);
			break;

		case EPL_AMNI:
			/* Currently all fields in the AMNI frame are reserved. Therefore
			 * there's nothing to dissect! Everything is given to the heuristic,
			 * which will dissect as data, if no heuristic dissector uses it. */
			size = tvb_captured_length_remaining(tvb, offset);
			offset = dissect_epl_payload(epl_tree, tvb, pinfo, offset, size, NULL, EPL_AMNI);
			break;

	           /* Default case can not happen as it is caught by an earlier switch
	            *                       statement */
	}


	return offset;
}

static int
dissect_epl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dissect_eplpdu(tvb, pinfo, tree, FALSE);
}

static int
dissect_epludp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dissect_eplpdu(tvb, pinfo, tree, TRUE);
}


const gchar*
decode_epl_address (guchar adr)
{
	const gchar *addr_str;

	addr_str = try_val_to_str(adr, addr_str_vals);

	if (addr_str != NULL)
	{
		return addr_str;
	}
	else
	{
		if (EPL_IS_CN_NODEID(adr))
		{
			return addr_str_cn;
		}
		else
		{
			return addr_str_res;
		}
	}
}

static gint
dissect_epl_payload(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, gint len, const struct epl_datatype *type, guint8 msgType)
{

	/* If a mapping uses a type of fixed width that's not equal to
	 * the function argument's length, fallback to raw data dissector
	 */
	if (type && (!type->len || type->len == len))
	{
		proto_tree_add_item(epl_tree, *type->hf, tvb, offset, len, type->encoding);
		offset += len;
	}
	else
	{
		gint off = 0, rem_len = 0, pld_rem_len = 0;
		tvbuff_t * payload_tvb = NULL;
		heur_dtbl_entry_t *hdtbl_entry = NULL;
		proto_item * item = NULL;

		off = offset;

		if (len > 0)
		{
			rem_len = tvb_captured_length_remaining(tvb, 0);
			payload_tvb = tvb_new_subset_length(tvb, off, len > rem_len ? rem_len : len);
			pld_rem_len = tvb_captured_length_remaining(payload_tvb, 0);
			if ( pld_rem_len < len )
			{
				item = proto_tree_add_uint(epl_tree, hf_epl_payload_real, tvb, off, pld_rem_len, pld_rem_len);
				PROTO_ITEM_SET_GENERATED(item);
				expert_add_info(pinfo, item, &ei_real_length_differs );
				if (pinfo->num == 376006)
					printf("topkek[%u]: pld_rem_len=%u, len=%u, rem_len=%u, off=%u\n", pinfo->num, pld_rem_len, len, rem_len, off);
			}

			if ( ! dissector_try_heuristic(heur_epl_data_subdissector_list, payload_tvb, pinfo, epl_tree, &hdtbl_entry, &msgType))
			{
				/* We don't know the type, so let's use appropriate unsignedX */
				gint *hf = SIZE_TO_UNSIGNED_HF(len);
				if (hf)
				{
					proto_tree_add_item(epl_tree, *hf, payload_tvb, 0, len, ENC_LITTLE_ENDIAN);
				} else {
					call_data_dissector(payload_tvb, pinfo, epl_tree);
				}
			}
		}

		offset = off + len;
	}

	return offset;
}

gint
dissect_epl_soc(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	nstime_t nettime;
	guint8  flags;
	static const int * soc_flags[] = {
		&hf_epl_soc_mc,
		&hf_epl_soc_ps,
		NULL
	};

	offset += 1;

	flags = tvb_get_guint8(tvb, offset);
	proto_tree_add_bitmask(epl_tree, tvb, offset, hf_epl_soc, ett_epl_soc, soc_flags, ENC_NA);

	offset += 2;

	if (show_soc_flags)
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "F:MC=%d,PS=%d",
				((EPL_SOC_MC_MASK & flags) >> 7), ((EPL_SOC_PS_MASK & flags) >> 6));
	}

	nettime.secs  = tvb_get_letohl(tvb, offset);
	nettime.nsecs = tvb_get_letohl(tvb, offset+4);
	proto_tree_add_time(epl_tree, hf_epl_soc_nettime, tvb, offset, 8, &nettime);

	proto_tree_add_item(epl_tree, hf_epl_soc_relativetime, tvb, offset+8, 8, ENC_LITTLE_ENDIAN);
	offset += 16;

	return offset;
}



gint
dissect_epl_preq(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	guint16 len;
	guint8  pdoversion;
	guint8  flags;
	static const int * req_flags[] = {
		&hf_epl_preq_ms,
		&hf_epl_preq_ea,
		&hf_epl_preq_rd,
		NULL
	};

	offset += 1;

	flags = tvb_get_guint8(tvb, offset);
	proto_tree_add_bitmask(epl_tree, tvb, offset, hf_epl_preq, ett_epl_preq, req_flags, ENC_NA);
	offset += 2;

	pdoversion = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(epl_tree, hf_epl_preq_pdov, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* get size of payload */
	len = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(epl_tree, hf_epl_preq_size, tvb, offset, 2, len);

	col_append_fstr(pinfo->cinfo, COL_INFO, "[%4d]  F:RD=%d  V:%d.%d", len,
			(EPL_PDO_RD_MASK & flags), hi_nibble(pdoversion), lo_nibble(pdoversion));

	offset += 2;
	offset = dissect_epl_pdo(convo, epl_tree, tvb, pinfo, offset, len, EPL_PREQ );

	return offset;
}



gint
dissect_epl_pres(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
	guint16  len;
	guint8  pdoversion;
	guint8  state, flags, flags2;
	static const int * res_flags[] = {
		&hf_epl_pres_ms,
		&hf_epl_pres_en,
		&hf_epl_pres_rd,
		NULL
	};

	state = tvb_get_guint8(tvb, offset);
	if (epl_src != EPL_MN_NODEID)   /* check if the sender is CN or MN */
	{
		proto_tree_add_item(epl_tree, hf_epl_pres_stat_cs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	else /* MN */
	{
		proto_tree_add_item(epl_tree, hf_epl_pres_stat_ms, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	offset += 1;

	flags = tvb_get_guint8(tvb, offset);
	proto_tree_add_bitmask(epl_tree, tvb, offset, hf_epl_pres, ett_epl_pres, res_flags, ENC_NA);
	offset += 1;

	flags2 = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(epl_tree, hf_epl_pres_pr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_tree, hf_epl_pres_rs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	pdoversion = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(epl_tree, hf_epl_pres_pdov, tvb, offset, 1, ENC_ASCII|ENC_NA);
	offset += 2;

	/* get size of payload */
	len = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(epl_tree, hf_epl_pres_size, tvb, offset, 2, len);

	col_append_fstr(pinfo->cinfo, COL_INFO, "[%4d]", len);

	col_append_fstr(pinfo->cinfo, COL_INFO, "  F:RD=%d,RS=%d,PR=%d  V=%d.%d",
			(EPL_PDO_RD_MASK & flags), (EPL_PDO_RS_MASK & flags2), (EPL_PDO_PR_MASK & flags2) >> 3,
			hi_nibble(pdoversion), lo_nibble(pdoversion));

	if (epl_src != EPL_MN_NODEID)   /* check if the sender is CN or MN */
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "  %s",
						val_to_str(state, epl_nmt_cs_vals, "Unknown(%d)"));
	}
	else /* MN */
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "  %s",
						val_to_str(state, epl_nmt_ms_vals, "Unknown(%d)"));
	}


	offset += 2;
	offset = dissect_epl_pdo(convo, epl_tree, tvb, pinfo, offset, len, EPL_PRES );

	return offset;
}


gint
dissect_epl_soa(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
	guint8 svid, target;
	guint8 state;
	proto_item *psf_item = NULL;
	proto_tree *psf_tree  = NULL;

	state = tvb_get_guint8(tvb, offset);
	if (epl_src != EPL_MN_NODEID)   /* check if CN or MN */
	{
		proto_tree_add_item(epl_tree, hf_epl_soa_stat_cs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	else /* MN */
	{
		proto_tree_add_item(epl_tree, hf_epl_soa_stat_ms, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}

	offset += 1;

	svid = tvb_get_guint8(tvb, offset + 2);
	if (svid == EPL_SOA_IDENTREQUEST)
	{
		proto_tree_add_item(epl_tree, hf_epl_soa_dna_an_lcl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	proto_tree_add_item(epl_tree, hf_epl_soa_dna_an_glb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_tree, hf_epl_soa_ea, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_tree, hf_epl_soa_er, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_uint(epl_tree, hf_epl_soa_svid, tvb, offset, 1, svid);
	offset += 1;

	target = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(epl_tree, hf_epl_soa_svtg, tvb, offset, 1, target);
	offset += 1;

	col_append_fstr(pinfo->cinfo, COL_INFO, "(%s)->%3d",
					rval_to_str(svid, soa_svid_id_vals, "Unknown"), target);

	if (epl_src != EPL_MN_NODEID)   /* check if CN or MN */
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "  %s",
						val_to_str(state, epl_nmt_cs_vals, "Unknown(%d)"));
	}
	else /* MN */
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "  %s",
						val_to_str(state, epl_nmt_ms_vals, "Unknown(%d)"));
	}

	proto_tree_add_item(epl_tree, hf_epl_soa_eplv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	if (svid == EPL_SOA_SYNCREQUEST)
	{
		/* reserved */
		offset +=1;
		/* SyncControl bit0-7 */
		psf_item = proto_tree_add_item(epl_tree, hf_epl_soa_sync, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(psf_item, " (Bits 0..7)");
		psf_tree = proto_item_add_subtree(psf_item, ett_epl_soa_sync);
		proto_tree_add_item(psf_tree, hf_epl_soa_mac, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(psf_tree, hf_epl_soa_pre_tm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(psf_tree, hf_epl_soa_mnd_sec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(psf_tree, hf_epl_soa_mnd_fst, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(psf_tree, hf_epl_soa_pre_sec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(psf_tree, hf_epl_soa_pre_fst, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		/* SyncControl 2 - reserved */
		psf_item = proto_tree_add_item(epl_tree, hf_epl_soa_sync, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(psf_item, " (Bits 8..15)");
#if 0
		psf_tree = proto_item_add_subtree(psf_item, ett_epl_soa_sync);
#endif
		offset += 1;
		/* SyncControl 3 - reserved */
		psf_item = proto_tree_add_item(epl_tree, hf_epl_soa_sync, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(psf_item, " (Bits 16..23)");
#if 0
		psf_tree = proto_item_add_subtree(psf_item, ett_epl_soa_sync);
#endif
		offset += 1;
		/* SyncControl 4 */
		psf_item = proto_tree_add_item(epl_tree, hf_epl_soa_sync, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(psf_item, " (Bits 24..31)");
		psf_tree = proto_item_add_subtree(psf_item, ett_epl_soa_sync);
		proto_tree_add_item(psf_tree, hf_epl_soa_pre_set, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(psf_tree, hf_epl_soa_pre_res, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		/* PResTimeFirst */
		proto_tree_add_item(epl_tree, hf_epl_soa_pre_fst_end, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		/* PResTimeSecond */
		proto_tree_add_item(epl_tree, hf_epl_soa_pre_sec_end, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		/* SyncMNDelayFirst */
		proto_tree_add_item(epl_tree, hf_epl_soa_mnd_fst_end, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		/* SyncMNDelaySecond */
		proto_tree_add_item(epl_tree, hf_epl_soa_mnd_sec_end, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		/* PResFallBackTimeout */
		proto_tree_add_item(epl_tree, hf_epl_soa_pre_tm_end, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		/* DestMacAddress */
		proto_tree_add_item(epl_tree, hf_epl_soa_mac_end, tvb, offset, 6, ENC_NA);
		offset += 6;
	}

	return offset;
}



gint
dissect_epl_asnd(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
	guint8  svid;
	gint size, reported_len;
	tvbuff_t *next_tvb;
	proto_item *item;
	proto_tree *subtree;

	/* get ServiceID of payload */
	svid = tvb_get_guint8(tvb, offset);
	item = proto_tree_add_uint(epl_tree, hf_epl_asnd_svid, tvb, offset, 1, svid );

	offset += 1;

	col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ",
			rval_to_str(svid, asnd_svid_id_vals, "Unknown"));

	switch (svid)
	{
		case EPL_ASND_IDENTRESPONSE:
			offset = dissect_epl_asnd_ires(convo, epl_tree, tvb, pinfo, epl_src, offset);
			break;

		case EPL_ASND_STATUSRESPONSE:
			offset = dissect_epl_asnd_sres(epl_tree, tvb, pinfo, epl_src, offset);
			break;

		case EPL_ASND_NMTREQUEST:
			offset = dissect_epl_asnd_nmtreq(epl_tree, tvb, pinfo, offset);
			break;

		case EPL_ASND_NMTCOMMAND:
			offset = dissect_epl_asnd_nmtcmd(epl_tree, tvb, pinfo, offset);
			break;

		case EPL_ASND_SDO:
			subtree = proto_item_add_subtree ( item, ett_epl_sdo );
			offset = dissect_epl_asnd_sdo(convo, subtree, tvb, pinfo, offset);
			break;
		case EPL_ASND_SYNCRESPONSE:
			offset = dissect_epl_asnd_resp(epl_tree, tvb, pinfo, offset);
			break;
		default:
			size = tvb_captured_length_remaining(tvb, offset);
			reported_len = tvb_reported_length_remaining(tvb, offset);

			next_tvb = tvb_new_subset(tvb, offset, size, reported_len);
			/* Manufacturer specific entries for ASND services */
			if (svid >= 0xA0 && svid < 0xFF
			&& dissector_try_uint(epl_asnd_dissector_table, svid, next_tvb, pinfo,
			( epl_tree != NULL ? epl_tree->parent : epl_tree )))
					break;

			dissect_epl_payload(epl_tree, tvb, pinfo, offset, size, NULL, EPL_ASND);
	}

	return offset;
}

gint
dissect_epl_ainv(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
	guint8 svid;
	proto_item *item;
	proto_tree *subtree;

	if (epl_src != EPL_MN_NODEID)   /* check if CN or MN */
	{
		proto_tree_add_item(epl_tree, hf_epl_soa_stat_cs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	else /* MN */
	{
		proto_tree_add_item(epl_tree, hf_epl_soa_stat_ms, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}

	offset += 2;

	proto_tree_add_item(epl_tree, hf_epl_soa_ea, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_tree, hf_epl_soa_er, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	svid = tvb_get_guint8(tvb, offset);

	col_append_fstr(pinfo->cinfo, COL_INFO, "(%s)  ", rval_to_str(svid, asnd_svid_id_vals, "UNKNOWN(%d)"));

	item = proto_tree_add_uint(epl_tree, hf_epl_asnd_svid, tvb, offset, 1, svid );
	offset += 1;

	switch (svid)
	{
		case EPL_ASND_IDENTRESPONSE:
			offset = dissect_epl_asnd_ires(convo, epl_tree, tvb, pinfo, epl_src, offset);
			break;

		case EPL_ASND_STATUSRESPONSE:
			offset = dissect_epl_asnd_sres(epl_tree, tvb, pinfo, epl_src, offset);
			break;

		case EPL_ASND_NMTREQUEST:
			offset = dissect_epl_asnd_nmtreq(epl_tree, tvb, pinfo, offset);
			break;

		case EPL_ASND_NMTCOMMAND:
			offset = dissect_epl_asnd_nmtcmd(epl_tree, tvb, pinfo, offset);
			break;

		case EPL_SOA_UNSPECIFIEDINVITE:
			proto_tree_add_item(epl_tree, hf_epl_asnd_svtg, tvb, offset, 1, ENC_LITTLE_ENDIAN );
			offset += 1;
			proto_tree_add_item(epl_tree, hf_epl_soa_eplv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			break;

		case EPL_ASND_SDO:
			subtree = proto_item_add_subtree ( item, ett_epl_sdo );
			offset = dissect_epl_asnd_sdo(convo, subtree, tvb, pinfo, offset);
			break;
	}

	return offset;
}


gint
dissect_epl_asnd_nmtreq(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	guint8 rcid;

	rcid = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(epl_tree, hf_epl_asnd_nmtrequest_rcid, tvb, offset, 1, rcid);
	proto_tree_add_item(epl_tree, hf_epl_asnd_nmtrequest_rct, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_tree, hf_epl_asnd_nmtrequest_rcd, tvb, offset+2, -1, ENC_NA);

	offset += 2;

	col_append_str(pinfo->cinfo, COL_INFO,
						val_to_str_ext(rcid, &asnd_cid_vals_ext, "Unknown (%d)"));

	return offset;
}

gint
dissect_epl_asnd_nmtdna(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	proto_item  *ti_dna;
	proto_tree  *epl_dna_tree;
	guint32     curr_node_num;
	guint32     new_node_num;
	guint32     lease_time;
	guint32     lease_time_s;
	nstime_t    us;
	static const int * dna_flags[] = {
		&hf_epl_asnd_nmtcommand_nmtdna_ltv,
		&hf_epl_asnd_nmtcommand_nmtdna_hpm,
		&hf_epl_asnd_nmtcommand_nmtdna_nnn,
		&hf_epl_asnd_nmtcommand_nmtdna_mac,
		&hf_epl_asnd_nmtcommand_nmtdna_cnn,
		NULL
	};

	ti_dna = proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_nmtdna, tvb, offset, EPL_SIZEOF_NMTCOMMAND_DNA, ENC_NA);
	epl_dna_tree = proto_item_add_subtree(ti_dna, ett_epl_feat);

	proto_tree_add_bitmask(epl_dna_tree, tvb, offset, hf_epl_asnd_nmtcommand_nmtdna_flags, ett_epl_asnd_nmt_dna, dna_flags, ENC_NA);
	offset += 1;

	proto_tree_add_item(epl_dna_tree, hf_epl_asnd_nmtcommand_nmtdna_currmac, tvb, offset, 6, ENC_NA);
	offset += 6;

	/* 64-bit mask specifying which hub ports are active (1) or inactive (0) */
	proto_tree_add_item(epl_dna_tree, hf_epl_asnd_nmtcommand_nmtdna_hubenmsk, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	proto_tree_add_item_ret_uint(epl_dna_tree, hf_epl_asnd_nmtcommand_nmtdna_currnn, tvb, offset, 4, ENC_LITTLE_ENDIAN, &curr_node_num);
	offset += 4;

	proto_tree_add_item_ret_uint (epl_dna_tree, hf_epl_asnd_nmtcommand_nmtdna_newnn, tvb, offset, 4, ENC_LITTLE_ENDIAN, &new_node_num);
	offset += 4;

	lease_time = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
	lease_time_s = lease_time / 1000000; /* us->s */
	us.nsecs = (lease_time - lease_time_s * 1000000) * 1000; /* us->ns */
	us.secs = lease_time_s;
	proto_tree_add_time(epl_dna_tree, hf_epl_asnd_nmtcommand_nmtdna_leasetime, tvb, offset, 4, &us);
	offset += 4;

	col_append_fstr(pinfo->cinfo, COL_INFO, ": %4d -> %4d", curr_node_num, new_node_num);

	return offset;
}


gint
dissect_epl_asnd_nmtcmd(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	guint8  epl_asnd_nmtcommand_cid;
	guint16 errorcode;

	epl_asnd_nmtcommand_cid = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(epl_tree, hf_epl_asnd_nmtcommand_cid, tvb, offset, 1, epl_asnd_nmtcommand_cid);
	offset += 2;

	col_append_str(pinfo->cinfo, COL_INFO, val_to_str_ext(epl_asnd_nmtcommand_cid, &asnd_cid_vals_ext, "Unknown(%d)"));

	switch (epl_asnd_nmtcommand_cid)
	{
		case EPL_ASND_NMTCOMMAND_NMTNETHOSTNAMESET:
			proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_nmtnethostnameset_hn, tvb, offset, 32, ENC_NA);
			offset += 32;
			break;

		case EPL_ASND_NMTCOMMAND_NMTFLUSHARPENTRY:
			proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_nmtflusharpentry_nid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;
			break;

		case EPL_ASND_NMTCOMMAND_NMTPUBLISHTIME:
			proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_nmtpublishtime_dt, tvb, offset, 6, ENC_NA);
			offset += 6;
			break;

		case EPL_ASND_NMTCOMMAND_NMTDNA:
			/* This byte is reserved for the other NMT commands but some flags are placed in it for DNA */
			offset -= 1;
			offset = dissect_epl_asnd_nmtdna(epl_tree, tvb, pinfo, offset);
			break;

		case EPL_ASND_NMTCOMMAND_NMTRESETNODE:
			errorcode = tvb_get_letohs(tvb, offset);
			if (errorcode != 0)
			{
				col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(errorcode, errorcode_vals, "Unknown Error(0x%04x"));
				proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_resetnode_reason, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			}
			else
				proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_cdat, tvb, offset, -1, ENC_NA);
			break;

		default:
			proto_tree_add_item(epl_tree, hf_epl_asnd_nmtcommand_cdat, tvb, offset, -1, ENC_NA);
	}

	return offset;
}



gint
dissect_epl_asnd_ires(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
	guint16 additional;
	guint32 epl_asnd_identresponse_ipa, epl_asnd_identresponse_snm, epl_asnd_identresponse_gtw;
	proto_item  *ti_feat, *ti;
	proto_tree  *epl_feat_tree;

	/* Cut off previous convo and begin a new one */
	convo = epl_convo_cutoff(convo);

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_en, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_ec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_pr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_rs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	if (epl_src != EPL_MN_NODEID)   /* check if CN or MN */
	{
		proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_stat_cs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	else /* MN */
	{
		proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_stat_ms, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	offset += 2;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_ever, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 2;

	/* decode FeatureFlags */
	ti_feat = proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_feat, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	epl_feat_tree = proto_item_add_subtree(ti_feat, ett_epl_feat);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit0, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit3, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit5, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit6, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit7, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit8, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit9, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bitA, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bitB, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bitC, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bitD, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bitE, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bitF, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit10, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit11, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit12, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit13, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_feat_tree, hf_epl_asnd_identresponse_feat_bit14, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_pis, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_pos, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	convo->ResponseTime = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_rst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 6;

	convo->DeviceType = tvb_get_letohs(tvb, offset);
	additional        = tvb_get_letohs(tvb, offset+2);
	proto_tree_add_string_format_value(epl_tree, hf_epl_asnd_identresponse_dt, tvb, offset,
								4, "", "Profile %d (%s), Additional Information: 0x%4.4X",
								convo->DeviceType, val_to_str_const(convo->DeviceType, epl_device_profiles, "Unknown Profile"), additional);

	ti = proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_profile, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	if (!convo->profiles.CN || !convo->profiles.CN->nodeid)
		epl_update_convo_cn_profile(convo);
	if (convo->profiles.CN)
	{
		if (convo->profiles.CN->name)
			proto_item_append_text(ti, " (%s)", convo->profiles.CN->name);
		if (convo->profiles.CN->path)
		{
			ti = proto_tree_add_string(epl_tree, hf_epl_asnd_identresponse_profile_path, tvb, offset, 2, convo->profiles.CN->path);
			PROTO_ITEM_SET_GENERATED(ti);
		}
	}

	offset += 4;

	convo->VendorId = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_vid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	convo->ProductCode = tvb_get_letohl(tvb, offset);
	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_productcode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_rno, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_sno, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_vex1, tvb, offset, 8, ENC_LITTLE_ENDIAN);
	offset += 8;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_vcd, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_vct, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_ad, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_at, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	epl_asnd_identresponse_ipa = tvb_get_ntohl(tvb, offset);
	proto_tree_add_ipv4(epl_tree , hf_epl_asnd_identresponse_ipa, tvb, offset, 4, epl_asnd_identresponse_ipa);
	offset += 4;

	epl_asnd_identresponse_snm = tvb_get_ntohl(tvb, offset);
	proto_tree_add_ipv4(epl_tree , hf_epl_asnd_identresponse_snm, tvb, offset, 4, epl_asnd_identresponse_snm);
	offset += 4;

	epl_asnd_identresponse_gtw = tvb_get_ntohl(tvb, offset);
	proto_tree_add_ipv4(epl_tree , hf_epl_asnd_identresponse_gtw, tvb, offset, 4, epl_asnd_identresponse_gtw);
	offset += 4;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_hn, tvb, offset, 32, ENC_ASCII|ENC_NA);
	offset += 32;

	proto_tree_add_item(epl_tree, hf_epl_asnd_identresponse_vex2, tvb, offset, 48, ENC_NA);
	offset += 48;

	col_append_str(pinfo->cinfo, COL_INFO, val_to_str(convo->DeviceType, epl_device_profiles, "Device Profile %d"));

	return offset;
}

gint
dissect_epl_asnd_resp(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo _U_, gint offset)
{
	proto_item *psf_item = NULL;
	proto_tree *psf_tree  = NULL;

	/* reserved 2 byte*/
	offset +=2;
	/* SyncStatus bit 0 - 7 */
	psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_syncResponse_sync, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_item_append_text(psf_item, " (Bits 0..7)");
	psf_tree = proto_item_add_subtree(psf_item, ett_epl_asnd_sync);
	proto_tree_add_item(psf_tree, hf_epl_asnd_syncResponse_sec_val, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(psf_tree, hf_epl_asnd_syncResponse_fst_val, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	/* SyncStatus bit 8 - 15 reserved */
	psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_syncResponse_sync, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_item_append_text(psf_item, " (Bits 8..15)");
#if 0
	psf_tree = proto_item_add_subtree(psf_item, ett_epl_asnd_sync);
#endif
	offset += 1;
	/* SyncStatus bit 16 - 23 reserved */
	psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_syncResponse_sync, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_item_append_text(psf_item, " (Bits 16..23)");
#if 0
	psf_tree = proto_item_add_subtree(psf_item, ett_epl_asnd_sync);
#endif
	offset += 1;
	/* SyncStatus bit 24 - 31 reserved */
	psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_syncResponse_sync, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_item_append_text(psf_item, " (Bits 24..31)");
	psf_tree = proto_item_add_subtree(psf_item, ett_epl_asnd_sync);
	proto_tree_add_item(psf_tree, hf_epl_asnd_syncResponse_mode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	/* Latency */
	proto_tree_add_item(epl_tree, hf_epl_asnd_syncResponse_latency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	/* SyncDelayStation */
	proto_tree_add_item(epl_tree, hf_epl_asnd_syncResponse_node, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	/* SyncDelay */
	proto_tree_add_item(epl_tree, hf_epl_asnd_syncResponse_delay, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	/* PResTimeFirst */
	proto_tree_add_item(epl_tree, hf_epl_asnd_syncResponse_pre_fst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	/* PResTimeSecond */
	proto_tree_add_item(epl_tree, hf_epl_asnd_syncResponse_pre_sec, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;
	return offset;
}

gint
dissect_epl_asnd_sres(proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, guint8 epl_src, gint offset)
{
	proto_item  *ti_el_entry, *ti_el_entry_type;
	proto_tree  *epl_seb_tree, *epl_el_tree, *epl_el_entry_tree, *epl_el_entry_type_tree;
	guint       number_of_entries, cnt;    /* used for dissection of ErrorCodeList */
	guint8      nmt_state;

	proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_en, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_ec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_pr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_tree, hf_epl_asnd_statusresponse_rs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	nmt_state = tvb_get_guint8(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%s   ", val_to_str(nmt_state, epl_nmt_cs_vals, "Unknown (%d)"));

	if (epl_src != EPL_MN_NODEID)   /* check if CN or MN */
	{
		proto_tree_add_uint(epl_tree, hf_epl_asnd_statusresponse_stat_cs, tvb, offset, 1, nmt_state);
	}
	else /* MN */
	{
		proto_tree_add_uint(epl_tree, hf_epl_asnd_statusresponse_stat_ms, tvb, offset, 1, nmt_state);
	}
	offset += 4;

	/* Subtree for the static error bitfield */
	epl_seb_tree = proto_tree_add_subtree(epl_tree, tvb, offset, 8, ett_epl_seb, NULL, "StaticErrorBitfield");

	proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(epl_seb_tree, hf_epl_asnd_statusresponse_seb_devicespecific_err, tvb,offset, 6, ENC_NA);
	offset += 6;

	/* List of errors / events */
	/* get the number of entries in the error code list*/
	number_of_entries = (tvb_reported_length(tvb)-offset)/20;

	epl_el_tree = proto_tree_add_subtree_format(epl_tree, tvb, offset, -1, ett_epl_el, NULL, "ErrorCodeList: %d entries", number_of_entries);

	/*Dissect the whole Error List (display each entry)*/
	for (cnt = 0; cnt<number_of_entries; cnt++)
	{
		epl_el_entry_tree = proto_tree_add_subtree_format(epl_el_tree, tvb, offset, 20, ett_epl_el_entry, &ti_el_entry, "Entry %d", cnt+1);

		/*Entry Type*/
		ti_el_entry_type = proto_tree_add_item(ti_el_entry,
							hf_epl_asnd_statusresponse_el_entry_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);

		epl_el_entry_type_tree = proto_item_add_subtree(ti_el_entry_type,
								ett_epl_el_entry_type);

		proto_tree_add_item(epl_el_entry_type_tree,
					hf_epl_asnd_statusresponse_el_entry_type_profile, tvb, offset, 2, ENC_LITTLE_ENDIAN);

		proto_tree_add_item(epl_el_entry_type_tree,
					hf_epl_asnd_statusresponse_el_entry_type_mode, tvb, offset, 2, ENC_LITTLE_ENDIAN);

		proto_tree_add_item(epl_el_entry_type_tree,
					hf_epl_asnd_statusresponse_el_entry_type_bit14, tvb, offset, 2, ENC_LITTLE_ENDIAN);

		proto_tree_add_item(epl_el_entry_type_tree,
					hf_epl_asnd_statusresponse_el_entry_type_bit15, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(epl_el_entry_tree, hf_epl_asnd_statusresponse_el_entry_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;

		proto_tree_add_item(epl_el_entry_tree, hf_epl_asnd_statusresponse_el_entry_time, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;

		proto_tree_add_item(epl_el_entry_tree, hf_epl_asnd_statusresponse_el_entry_add, tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
	}

	return offset;
}

gint
dissect_epl_asnd_sdo(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	guint16 seqnum = 0x00;
	offset = dissect_epl_sdo_sequence(convo, epl_tree, tvb, pinfo, offset);

	seqnum = epl_get_sequence_nr(pinfo);

	/* if a frame is duplicated don't show the command layer */
	if(seqnum == 0x00 || show_cmd_layer_for_duplicated == TRUE )
	{
		if (tvb_reported_length_remaining(tvb, offset) > 0)
		{
			offset = dissect_epl_sdo_command(convo, epl_tree, tvb, pinfo, offset);
		}
		else col_append_str(pinfo->cinfo, COL_INFO, "Empty CommandLayer");
	}
	return offset;
}

gint
dissect_epl_sdo_sequence(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	guint8 seq_recv = 0x00, seq_send = 0x00, rcon = 0x00, scon = 0x00;
	guint32 frame = 0x00;
	proto_tree *sod_seq_tree;
	proto_item *item;
	guint8 duplication = 0x00;
	gpointer key;
	guint32 saved_frame;
	guint16 seqnum = 0;

	/* read buffer */
	seq_recv = tvb_get_guint8(tvb, offset);
	/* get rcon */
	rcon = seq_recv & EPL_ASND_SDO_SEQ_CON_MASK;
	/* get seq_recv */
	seq_recv = seq_recv >> EPL_ASND_SDO_SEQ_MASK;
	epl_segmentation.recv = seq_recv;
	/* read buffer */
	seq_send = tvb_get_guint8(tvb, offset+1);
	/* get scon */
	scon = seq_send & EPL_ASND_SDO_SEQ_CON_MASK;
	/* get seq_send */
	seq_send = seq_send >> EPL_ASND_SDO_SEQ_MASK;
	epl_segmentation.send = seq_send;
	/* get the current frame-number */
	frame = pinfo->num;

	/* Create a key */
	key = epl_duplication_key(epl_segmentation.src,epl_segmentation.dest,seq_recv,seq_send);

	/* Get the saved data */
	saved_frame = epl_duplication_get(epl_duplication_table, key);

	/* clear array at the start Sequence */
	if((rcon < EPL_VALID && scon < EPL_VALID)
		||(rcon == EPL_VALID && scon < EPL_VALID)
		||(rcon < EPL_VALID && scon == EPL_VALID))
	{
		/* remove all the keys of the specified src and dest address*/
		epl_duplication_remove(epl_duplication_table,epl_segmentation.src,epl_segmentation.dest);
		/* There is no cmd layer */
		epl_set_sequence_nr(pinfo, 0x02);
	}
	/* if cooked/fuzzed capture*/
	else if(seq_recv >= EPL_MAX_SEQUENCE || seq_send >= EPL_MAX_SEQUENCE
			||rcon > EPL_RETRANSMISSION || scon > EPL_RETRANSMISSION )
	{
		if(seq_recv >= EPL_MAX_SEQUENCE)
		{
			expert_add_info(pinfo, epl_tree, &ei_recvseq_value);
		}
		if(seq_send >= EPL_MAX_SEQUENCE)
		{
			expert_add_info(pinfo, epl_tree, &ei_sendseq_value);
		}
		if(rcon > EPL_RETRANSMISSION)
		{
			expert_add_info(pinfo, epl_tree, &ei_recvcon_value);
		}
		if(scon > EPL_RETRANSMISSION)
		{
			expert_add_info(pinfo, epl_tree, &ei_sendcon_value);
		}
		duplication = 0x00;
		epl_set_sequence_nr(pinfo, 0x00);
	}
	else
	{
		/* if retransmission request or connection valid with acknowledge request */
		if((rcon == EPL_VALID && scon == EPL_RETRANSMISSION) || (rcon == EPL_RETRANSMISSION && scon == EPL_VALID))
		{
			/* replace the saved frame with the new frame */
			epl_duplication_insert(epl_duplication_table, key, frame);
		}
		/* if connection valid */
		else
		{
			/* store the new frame in the hash table */
			if(saved_frame == 0x00)
			{
				/* store the new frame in the hash table */
				epl_duplication_insert(epl_duplication_table,key,frame);
			}
			/* if the frame is bigger than the stored frame + the max frame offset
			   or the saved frame is bigger that the current frame then store the current
			   frame */
			else if(((frame > (saved_frame + EPL_MAX_FRAME_OFFSET))
				||(saved_frame > frame)))
			{
				/* store the new frame in the hash table */
				epl_duplication_insert(epl_duplication_table,key,frame);
			}
			else if((frame < (saved_frame + EPL_MAX_FRAME_OFFSET))
				&&(frame > saved_frame))
			{
				duplication = 0x01;
			}
		}
	}
	/* if the frame is a duplicated frame */
	seqnum = epl_get_sequence_nr(pinfo);
	if((duplication == 0x01 && seqnum == 0x00)||(seqnum == 0x01))
	{
		seqnum = 0x01;
		epl_set_sequence_nr(pinfo, seqnum);
		expert_add_info_format(pinfo, epl_tree, &ei_duplicated_frame,
			"Duplication of Frame: %d ReceiveSequenceNumber: %d and SendSequenceNumber: %d ",
			saved_frame,seq_recv,seq_send );
	}
	/* if the last frame in the ReceiveSequence is sent get new memory */
	if(seq_recv == 0x3f && seq_send <= 0x3f)
	{
		/* reset all entries of the transfer */
		epl_duplication_remove(epl_duplication_table,epl_segmentation.src,epl_segmentation.dest);
	}
	free_key(key);
	item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_seq, tvb,  offset, 5, ENC_NA);
	sod_seq_tree = proto_item_add_subtree(item, ett_epl_sdo_sequence_layer);
	/* Asynchronuous SDO Sequence Layer */
	seq_recv = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(sod_seq_tree, hf_epl_asnd_sdo_seq_receive_sequence_number, tvb, offset, 1, seq_recv);
	proto_tree_add_uint(sod_seq_tree, hf_epl_asnd_sdo_seq_receive_con,             tvb, offset, 1, seq_recv);
	offset += 1;

	convo->seq_send = seq_send = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(sod_seq_tree, hf_epl_asnd_sdo_seq_send_sequence_number, tvb, offset, 1, seq_send);
	proto_tree_add_uint(sod_seq_tree, hf_epl_asnd_sdo_seq_send_con, tvb, offset, 1, seq_send);
	offset += 3;

	col_append_fstr(pinfo->cinfo, COL_INFO, "Seq:%02d%s,%02d%s",
					seq_recv >> EPL_ASND_SDO_SEQ_MASK, val_to_str(seq_recv & EPL_ASND_SDO_SEQ_CON_MASK, epl_sdo_init_abbr_vals, "x"),
					seq_send >> EPL_ASND_SDO_SEQ_MASK, val_to_str(seq_send & EPL_ASND_SDO_SEQ_CON_MASK, epl_sdo_init_abbr_vals, "x"));

	seq_recv &= EPL_ASND_SDO_SEQ_CON_MASK;
	seq_send &= EPL_ASND_SDO_SEQ_CON_MASK;

	col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ", val_to_str((seq_recv << 8) | seq_send, epl_sdo_init_con_vals, "Invalid"));

	return offset;
}

gint
dissect_epl_sdo_command(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset)
{
	gint    payload_length;
	guint8  segmented, command_id, transaction_id;
	gboolean response, abort_flag;
	guint32 abort_code = 0;
	guint32 fragmentId = 0, remlength = 0;
	guint16 segment_size = 0;
	proto_tree *sdo_cmd_tree = NULL;
	proto_item *item;
	guint8 sendCon = 0;

	offset += 1;

	sendCon = tvb_get_guint8(tvb, 5) & EPL_ASND_SDO_SEQ_SEND_CON_ERROR_VALID_ACK_REQ;

	command_id = tvb_get_guint8(tvb, offset + 2);
	abort_flag = tvb_get_guint8(tvb, offset + 1) & EPL_ASND_SDO_CMD_ABORT_FILTER;

	/* test if CommandField == empty */
	if (command_id != 0 || abort_flag)
	{
		item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd, tvb,  offset, 0, ENC_NA);
		sdo_cmd_tree = proto_item_add_subtree(item, ett_epl_sdo_command_layer);

		transaction_id = tvb_get_guint8(tvb, offset);
		response   = tvb_get_guint8(tvb, offset + 1) & EPL_ASND_SDO_CMD_RESPONSE_FILTER;
		segmented  = (tvb_get_guint8(tvb, offset + 1) & EPL_ASND_SDO_CMD_SEGMENTATION_FILTER) >> 4;

		segment_size = tvb_get_letohs(tvb, offset + 3);

		col_append_fstr(pinfo->cinfo, COL_INFO, "Cmd:%s,TID=%02d ",
						val_to_str(segmented, epl_sdo_asnd_cmd_segmentation_abbr, " Inv(%d)"), transaction_id);

		proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_transaction_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_response, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_abort,    tvb, offset, 1, ENC_LITTLE_ENDIAN);

		proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_segmentation, tvb, offset, 1, ENC_LITTLE_ENDIAN);

		if (segment_size != 0)
		{
			offset += 1;
			proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_command_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_segment_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 4;
		}
		/* adjust size of packet */
		tvb_set_reported_length(tvb, offset + segment_size);

		if (segmented == EPL_ASND_SDO_CMD_SEGMENTATION_INITIATE_TRANSFER)
		{
			if((command_id == EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX) || (command_id == EPL_ASND_SDO_COMMAND_READ_BY_INDEX))
			{
				if (sendCon != EPL_ASND_SDO_SEQ_SEND_CON_ERROR_VALID_ACK_REQ)
				{
					/* if download => reset counter */
					if(command_id == EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX)
						ct = 0x00;
					/* if upload => reset counter */
					else if(command_id == EPL_ASND_SDO_COMMAND_READ_BY_INDEX)
						count = 0x00;
				}
				/* payload length */
				payload_length = tvb_reported_length_remaining(tvb, offset);
				/* create a key for reassembly => first 16 bit are src-address and
				last 16 bit are the dest-address */
				fragmentId = (guint32)((((guint32)epl_segmentation.src)<<16)+epl_segmentation.dest);
				/* set fragmented flag */
				pinfo->fragmented = TRUE;
				fragment_add_seq_check(&epl_reassembly_table, tvb, offset, pinfo,
												fragmentId, NULL, 0, payload_length, TRUE );
				fragment_add_seq_offset ( &epl_reassembly_table, pinfo, fragmentId, NULL, 0 );
				if (command_id == EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX)
				{
					first_write = FALSE;
				}
				else
				{
					first_read = FALSE;
				}
				/* if Segmentation = Initiate then print DataSize */
				proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				segmented = TRUE;

				offset += 4;
			}
			else
			{
				/* if Segmentation = Initiate then print DataSize */
				proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_data_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
				segmented = TRUE;
				offset += 4;
			}
		}
		if (abort_flag)
		{
			remlength = tvb_captured_length_remaining(tvb, offset);
			if (command_id == EPL_ASND_SDO_COMMAND_WRITE_MULTIPLE_PARAMETER_BY_INDEX && response)
			{
				/* the SDO response can contain several abort codes for multiple transfers */
				while (remlength > 0)
				{
					proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_data_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
					offset += 2;

					proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;

					proto_tree_add_item(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_sub_abort, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;

					abort_code = tvb_get_letohl(tvb, offset);
					/* if AbortBit is set then print AbortMessage */
					proto_tree_add_uint(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_abort_code, tvb, offset, 4, abort_code);
					col_append_fstr(pinfo->cinfo, COL_INFO, "Abort:0x%08X (%s)", abort_code, val_to_str_ext_const(abort_code, &sdo_cmd_abort_code_ext, "Unknown"));
					offset += 4;

					remlength = tvb_captured_length_remaining(tvb, offset);
				}
			}
			else
			{
				abort_code = tvb_get_letohl(tvb, offset);
				/* if AbortBit is set then print AbortMessage */
				proto_tree_add_uint(sdo_cmd_tree, hf_epl_asnd_sdo_cmd_abort_code, tvb, offset, 4, abort_code);
				col_append_fstr(pinfo->cinfo, COL_INFO, "Abort:0x%08X (%s)", abort_code, val_to_str_ext_const(abort_code, &sdo_cmd_abort_code_ext, "Unknown"));
			}
		}
		else
		{
			switch (command_id)
			{
			case EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX:
				offset = dissect_epl_sdo_command_write_by_index(convo, sdo_cmd_tree, tvb, pinfo, offset, segmented, response, segment_size);
				break;

			case EPL_ASND_SDO_COMMAND_WRITE_MULTIPLE_PARAMETER_BY_INDEX:
				offset = dissect_epl_sdo_command_write_multiple_by_index(convo, sdo_cmd_tree, tvb, pinfo, offset, segmented, response, segment_size);
				break;

			case EPL_ASND_SDO_COMMAND_READ_BY_INDEX:
				offset = dissect_epl_sdo_command_read_by_index(convo, sdo_cmd_tree, tvb, pinfo, offset, segmented, response, segment_size);
				break;

			default:
				return FALSE;
			}
		}
	}
	return offset;
}

gint
dissect_epl_sdo_command_write_by_index(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 segmented, gboolean response, guint16 segment_size)
{
	gint size, payload_length = 0;
	guint16 idx = 0x00, param_index = 0x00, sod_index = 0x00, error = 0xFF, sub_val = 0x00;
	gboolean nosub = FALSE;
	guint8 subindex = 0x00, param_subindex = 0x00;
	guint32 fragmentId = 0;
	guint32 frame = 0;
	gboolean end_segment = FALSE;
	proto_item *psf_item, *cmd_payload;
	proto_tree *payload_tree;
	const gchar *index_str, *sub_str, *sub_index_str;
	fragment_head *frag_msg = NULL;
	struct object *obj = NULL;
	struct subobject *subobj = NULL;

	/* get the current frame number */
	frame = pinfo->num;

	if (!response)
	{   /* request */

		if (segmented <= EPL_ASND_SDO_CMD_SEGMENTATION_INITIATE_TRANSFER)
		{
			/* get index offset */
			param_index = idx = tvb_get_letohs(tvb, offset);
			/* add index item */
			psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			/* look up index in registered profile */
			obj = object_lookup(convo->profiles.CN, idx);
			if (!obj)
			{
				/* value to string */
				index_str = rval_to_str_const(idx, sod_cmd_str, "unknown");
				/* get index string value */
				sod_index = str_to_val(index_str, sod_cmd_str_val, error);

				/* get subindex string */
				sub_index_str = val_to_str_ext_const(idx, &sod_cmd_no_sub, "unknown");
				/* get subindex string value */
				nosub = str_to_val(sub_index_str, sod_cmd_str_no_sub, 0xFF) != 0xFF;
			}
			offset += 2;

			/* get subindex offset */
			param_subindex = subindex = tvb_get_guint8(tvb, offset);
			subobj = subobject_lookup(obj, subindex);


			/* get subindex string */
			sub_str = val_to_str_ext_const(idx, &sod_cmd_sub_str, "unknown");
			/* get string value */
			sub_val = str_to_val(sub_str, sod_cmd_sub_str_val, error);

			col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%d]: (0x%04X/%d)",
							val_to_str_ext(EPL_ASND_SDO_COMMAND_WRITE_BY_INDEX, &epl_sdo_asnd_commands_short_ext, "Command(%02X)"),
							segment_size, idx, subindex);

			if(obj)
			{
				const char *name = obj->info.name;
				proto_item_append_text(psf_item, " (%s)", name);
				col_append_fstr(pinfo->cinfo, COL_INFO, " (%s", name);
				nosub = obj->info.kind == OD_ENTRY_NO_SUBINDICES;
			}
			else if (sod_index == error)
			{
				const char *name = val_to_str_ext_const(((guint32)(idx<<16)), &sod_index_names, "User Defined");
				proto_item_append_text(psf_item, " (%s)", name);
				col_append_fstr(pinfo->cinfo, COL_INFO, " (%s", name);
			}
			else /* string is in list */
			{
				/* add index string to index item */
				proto_item_append_text(psf_item," (%s", val_to_str_ext_const(((guint32)(sod_index<<16)), &sod_index_names, "User Defined"));
				proto_item_append_text(psf_item,"_%02Xh", (idx-sod_index));
				if(sod_index == EPL_SOD_PDO_RX_MAPP || sod_index == EPL_SOD_PDO_TX_MAPP)
				{
					proto_item_append_text(psf_item,"_AU64)");
				}
				else
				{
					proto_item_append_text(psf_item,"_REC)");
				}
				/* info text */
				col_append_fstr(pinfo->cinfo, COL_INFO, " (%s", val_to_str_ext_const(((guint32)(sod_index << 16)), &sod_index_names, "User Defined"));
				col_append_fstr(pinfo->cinfo, COL_INFO, "_%02Xh", (idx-sod_index));
				if(sod_index == EPL_SOD_PDO_RX_MAPP || sod_index == EPL_SOD_PDO_TX_MAPP)
				{
					col_append_fstr(pinfo->cinfo, COL_INFO, "_AU64");
				}
				else
				{
					col_append_fstr(pinfo->cinfo, COL_INFO, "_REC");
				}
				idx = sod_index;
			}

			if(sub_val != error)
				idx = sub_val;

			if (subobj)
			{
				psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_item_append_text(psf_item, " (%s)", subobj->info.name);
				col_append_fstr(pinfo->cinfo, COL_INFO, "/%s)", subobj->info.name);
			}
			/* if the subindex is a EPL_SOD_STORE_PARAM */
			/* if the subindex is a EPL_SOD_RESTORE_PARAM */
			else if((idx == EPL_SOD_STORE_PARAM && subindex <= 0x7F && subindex >= 0x04) ||
					(idx == EPL_SOD_RESTORE_PARAM && subindex <= 0x7F && subindex >= 0x04))
			{
				psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_item_append_text(psf_item, " (ManufacturerParam_%02Xh_U32)", subindex);
				col_append_fstr(pinfo->cinfo, COL_INFO, "/ManufacturerParam_%02Xh_U32)", subindex);
			}
			/* if the subindex is a EPL_SOD_PDO_RX_MAPP */
			/* if the subindex is a EPL_SOD_PDO_TX_MAPP */
			else if((idx == EPL_SOD_PDO_RX_MAPP && subindex >= 0x01 && subindex <= 0xfe) ||
					(idx == EPL_SOD_PDO_TX_MAPP && subindex >= 0x01 && subindex <= 0xfe))
			{
				psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_item_append_text(psf_item, " (ObjectMapping)");
				col_append_fstr(pinfo->cinfo, COL_INFO, "/ObjectMapping)");
			}
			/* no subindex */
			else if(nosub)
			{
				col_append_fstr(pinfo->cinfo, COL_INFO, ")");
			}
			else if(subindex == 0x00)
			{
				psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_item_append_text(psf_item, " (NumberOfEntries)");
				col_append_fstr(pinfo->cinfo, COL_INFO, "/NumberOfEntries)");
			}
			else
			{
				psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				proto_item_append_text(psf_item, " (%s)", val_to_str_ext_const((subindex | (idx << 16)), &sod_index_names, "User Defined"));
				col_append_fstr(pinfo->cinfo, COL_INFO, "/%s)",val_to_str_ext_const((subindex | (idx << 16)), &sod_index_names, "User Defined"));
			}
			offset += 2;
		}
		/* Download */
		else if((segmented == EPL_ASND_SDO_CMD_SEGMENTATION_TRANSFER_COMPLETE) ||
			(segmented == EPL_ASND_SDO_CMD_SEGMENTATION_SEGMENT))
		{
			/* get the fragmentId */
			fragmentId = (guint32)((((guint32)epl_segmentation.src)<<16)+epl_segmentation.dest);
			/* set the fragmented flag */
			pinfo->fragmented = TRUE;

			/* get payloade size */
			payload_length = tvb_reported_length_remaining(tvb, offset);
			/* if the frame is the last frame */
			if(segmented == EPL_ASND_SDO_CMD_SEGMENTATION_TRANSFER_COMPLETE)
				end_segment = TRUE;

			/* if the send-sequence-number is at the end or the beginning of a sequence */
			if(epl_segmentation.send == 0x3f || epl_segmentation.send <= 0x01 )
			{
				/* reset memory */
				memset(&epl_asnd_sdo_reassembly_write,0,sizeof(epl_sdo_reassembly));
				/* save the current frame and increase the counter */
				epl_asnd_sdo_reassembly_write.frame[epl_segmentation.recv][epl_segmentation.send] = frame;
				ct += 1;
				/* add the frame to reassembly_table */
				frag_msg = fragment_add_seq_check(&epl_reassembly_table, tvb, offset, pinfo,
							  fragmentId, NULL, ct, payload_length, end_segment ? FALSE : TRUE );
			}
			else
			{
				if(epl_asnd_sdo_reassembly_write.frame[epl_segmentation.recv][epl_segmentation.send] == 0x00)
				{
					/* save the current frame and increase counter */
					epl_asnd_sdo_reassembly_write.frame[epl_segmentation.recv][epl_segmentation.send] = frame;
					ct += 1;
					/* add the frame to reassembly_table */
					if (first_write)
					{
						frag_msg = fragment_add_seq_check(&epl_reassembly_table, tvb, offset, pinfo,
							fragmentId, NULL, 0, payload_length, end_segment ? FALSE : TRUE );
						fragment_add_seq_offset(&epl_reassembly_table, pinfo, fragmentId, NULL, ct);

						first_write = FALSE;
					}
					else
					{
						frag_msg = fragment_add_seq_check(&epl_reassembly_table, tvb, offset, pinfo,
							fragmentId, NULL, ct, payload_length, end_segment ? FALSE : TRUE );
					}
				}
				else
				{
					frag_msg = fragment_add_seq_check(&epl_reassembly_table, tvb, offset, pinfo,
						fragmentId, NULL, 0, payload_length, end_segment ? FALSE : TRUE);
					epl_asnd_sdo_reassembly_write.frame[epl_segmentation.recv][epl_segmentation.send] = frame;
				}
			}

			/* if the reassembly_table is not Null and the frame stored is the same as the current frame */
			if(frag_msg != NULL && (epl_asnd_sdo_reassembly_write.frame[epl_segmentation.recv][epl_segmentation.send] == frame))
			{
				/* if the frame is the last frame */
				if(end_segment)
				{
					cmd_payload = proto_tree_add_uint_format(epl_tree, hf_epl_asnd_sdo_cmd_reassembled, tvb, offset, payload_length,0,
															"Reassembled: %d bytes total (%d bytes in this frame)",frag_msg->len,payload_length);
					payload_tree = proto_item_add_subtree(cmd_payload, ett_epl_asnd_sdo_data_reassembled);
					/* add the reassembley fields */
					process_reassembled_data(tvb, 0, pinfo, "Reassembled Message", frag_msg, &epl_frag_items, NULL, payload_tree );
					proto_tree_add_uint_format_value(payload_tree, hf_epl_asnd_sdo_cmd_reassembled, tvb, 0, 0,
									payload_length, "%d bytes (over all fragments)", frag_msg->len);
					col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)" );
				}
				else
				{
					cmd_payload = proto_tree_add_uint_format(epl_tree, hf_epl_asnd_sdo_cmd_reassembled, tvb, offset, payload_length,0,
														"Reassembled: %d bytes total (%d bytes in this frame)",frag_msg->len,payload_length);
					payload_tree = proto_item_add_subtree(cmd_payload, ett_epl_asnd_sdo_data_reassembled);
					/* add reassemble field => Reassembled in: */
					process_reassembled_data(tvb, 0, pinfo, "Reassembled Message", frag_msg, &epl_frag_items, NULL, payload_tree );
				}
				first_write = TRUE;
				ct = 0;
			}
		}
		size = tvb_reported_length_remaining(tvb, offset);


		/* if the frame is a PDO Mapping and the subindex is bigger than 0x00 */
		if((idx == EPL_SOD_PDO_TX_MAPP && subindex > 0x00) || (idx == EPL_SOD_PDO_RX_MAPP && subindex > 0x00))
		{
			wmem_array_t *mappings = idx == EPL_SOD_PDO_TX_MAPP ? convo->TPDO : convo->RPDO;
			offset = dissect_object_mapping(convo->profiles.CN, mappings, epl_tree, tvb, pinfo->num, offset, idx, subindex);
		}
		else
		{
			offset = dissect_epl_payload(epl_tree, tvb, pinfo, offset, size,
					obj ? obj->info.type : NULL, EPL_ASND);
		}
	}
	else
	{
		/* response, no payload */
		col_append_str(pinfo->cinfo, COL_INFO, "Response");
	}
	return offset;
}

/** epl_tree may be null here, when this function is called from the profile parser */
static gint
dissect_object_mapping(struct profile *profile, wmem_array_t *mappings, proto_tree *epl_tree, tvbuff_t *tvb, guint32 framenum, gint offset, guint16 idx, guint8 subindex)
{
	proto_item *ti_obj, *ti_subobj, *psf_item;
	proto_tree *psf_tree;
	struct object_mapping map = {0};
	struct object *mapping_obj;
	int *ett;
	struct subobject *mapping_subobj;
	gboolean nosub = FALSE;

	map.param.idx = idx;
	map.param.subindex = subindex;
	map.frame.first = framenum;
	map.frame.last  = G_MAXUINT32;

	psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_mapping, tvb, offset, 1, ENC_NA);
	psf_tree = proto_item_add_subtree(psf_item, ett_epl_asnd_sdo_cmd_data_mapping);

	map.pdo.idx = tvb_get_letohs(tvb, offset);
	ti_obj = proto_tree_add_uint_format(psf_tree, hf_epl_asnd_sdo_cmd_data_mapping_index, tvb, offset, 2, map.pdo.idx,"Index: 0x%04X", map.pdo.idx);
	offset += 2;

	map.pdo.subindex = tvb_get_guint8(tvb, offset);
	ti_subobj = proto_tree_add_uint_format(psf_tree, hf_epl_asnd_sdo_cmd_data_mapping_subindex, tvb, offset, 1, map.pdo.subindex, "SubIndex: 0x%02X", map.pdo.subindex);
	offset += 2;

	/* look up index in registered profiles */
	if ((mapping_obj = object_lookup(profile, map.pdo.idx)))
	{
		if (!map.pdo.subindex && mapping_obj->info.kind == OD_ENTRY_NO_SUBINDICES)
			nosub = TRUE;
	
		map.info = &mapping_obj->info;
		map.index_name = map.info->name;
		proto_item_append_text (ti_obj, " (%s)", map.info->name);

		mapping_subobj = subobject_lookup(mapping_obj, map.pdo.subindex);
		if (mapping_subobj)
		{
			map.info = &mapping_subobj->info;
			proto_item_append_text (ti_subobj, " (%s)", map.info->name);
		} else {
			PROTO_ITEM_SET_HIDDEN(ti_subobj);
		}
	}

	map.bit_offset = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint_format(psf_tree, hf_epl_asnd_sdo_cmd_data_mapping_offset, tvb, offset, 2, map.bit_offset,"Offset: 0x%04X", map.bit_offset);
	offset += 2;

	map.no_of_bits = tvb_get_guint8(tvb, offset);
	psf_item = proto_tree_add_item(psf_tree, hf_epl_asnd_sdo_cmd_data_mapping_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	proto_item_append_text(psf_item, " bits");
	offset += 2;


	/* TODO: Better representation?
	 * maybe Digital.Output_00h_AU8.DigitalOutput: 128 (0x80) ? */
	if (nosub)
		map.title = g_strdup_printf("PDO - %04X", map.pdo.idx);
	else
		map.title = g_strdup_printf("PDO - %04X:%02X", map.pdo.idx, map.pdo.subindex);


	map.ett = -1;
	ett = &map.ett;
	/* We leak an ett entry every time we destruct a mapping
	 * Not sure what to do about that
	 */
	proto_register_subtree_array(&ett, 1);

	add_object_mapping(mappings, &map);

	return offset;
}

gint
dissect_epl_sdo_command_write_multiple_by_index(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 segmented, gboolean response, guint16 segment_size)
{
	gint dataoffset;
	guint8 subindex = 0x00,  padding = 0x00;
	guint16 idx = 0x00, sod_index = 0x00, nosub = 0x00 ,error = 0xFF, sub_val = 0x00;
	guint32 size, offsetincrement, datalength, remlength, objectcnt;
	gboolean lastentry = FALSE;
	const gchar *index_str, *sub_str, *sub_index_str;
	proto_item *psf_item;
	proto_tree *psf_od_tree;
	struct object *obj = NULL;
	struct subobject *subobj = NULL;


	/* Offset is calculated simply by only applying EPL payload offset, not packet offset.
	* The packet offset is 16, as this is the number of bytes trailing the SDO payload.
	* EPL_SOA_EPLV_OFFSET has to be recognized, because the increment of PLK SDO payloads
	* is calculated, starting with the byte position AFTER the Sequence Layer.
	*/
	if (!response)
	{   /* request */

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%d]:",
				val_to_str_ext(EPL_ASND_SDO_COMMAND_WRITE_MULTIPLE_PARAMETER_BY_INDEX,
				&epl_sdo_asnd_commands_short_ext, "Command(%02X)"),
				segment_size);

		remlength = (guint32)tvb_reported_length_remaining(tvb, offset);
		objectcnt = 0;

		/* As long as no lastentry has been detected, and we have still bytes left,
		 * we start the loop. lastentry is probably not necessary anymore, since
		 * we now use length_remaining, but it is kept to be on the safe side. */
		while ( !lastentry && remlength > 0 )
		{

			offsetincrement = tvb_get_letohl(tvb, offset);

			/* the data is aligned in 4-byte increments, therfore maximum padding is 3 */
			padding = tvb_get_guint8 ( tvb, offset + 7 ) & 0x03;

			datalength = offsetincrement - ( offset - EPL_SOA_EPLV_OFFSET );
			/* An offset increment of zero usually indicates, that we are at the end
			 * of the payload. But we cannot ignore the end, because packages are
			 * stacked up until the last byte */
			if ( offsetincrement == 0 )
				datalength = remlength - EPL_SOA_EPLV_OFFSET;

			/* Possible guint overflow */
			if ( ( datalength + EPL_SOA_EPLV_OFFSET ) > remlength )
				break;

			/* Last frame detected */
			if ( offsetincrement == 0 )
			{
				datalength = remlength;

				/* guarding size against remaining length */
				if ( remlength < EPL_SOA_EPLV_OFFSET )
					break;

				size = remlength - EPL_SOA_EPLV_OFFSET;
				lastentry = TRUE;
			}
			else
			{
				/* Each entry has a header size of 8, based on the following calculation:
				 *   - 4 byte for byte position of next data set
				 *   - 2 byte for index
				 *   - 1 byte for subindex
				 *   - 1 byte for reserved and padding */

				/* Guarding against readout of padding. Probability is nearly zero, as
				 * padding was checked above, but to be sure, this remains here */
				if ( (guint32)( padding + 8 ) >= datalength )
					break;

				/* size of data is datalength - ( entry header size and padding ) */
				size = datalength - 8 - padding;
			}

			dataoffset = offset + 4;

			/* add object subtree */
			psf_od_tree = proto_tree_add_subtree(epl_tree, tvb, offset+4, 4+size, 0, NULL , "OD");

			if (segmented <= EPL_ASND_SDO_CMD_SEGMENTATION_INITIATE_TRANSFER)
			{
				/* get SDO index value */
				idx = tvb_get_letohs(tvb, dataoffset);
				/* add index item */
				psf_item = proto_tree_add_item(psf_od_tree, hf_epl_asnd_sdo_cmd_data_index, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);
				/* Check profile for name */
				obj = object_lookup(convo->profiles.CN, idx);
				if (!obj)
				{
					/* value to string */
					index_str = rval_to_str_const(idx, sod_cmd_str, "unknown");
					/* get index string value */
					sod_index = str_to_val(index_str, sod_cmd_str_val, error);

					/* get subindex string */
					sub_index_str = val_to_str_ext_const(idx, &sod_cmd_no_sub, "unknown");
					/* get subindex string value*/
					nosub = str_to_val(sub_index_str, sod_cmd_str_no_sub,error);
				}

				if(obj || sod_index == error)
				{
					const char *name = obj ? obj->info.name :val_to_str_ext_const(((guint32)(idx<<16)), &sod_index_names, "User Defined");
					proto_item_append_text(psf_item," (%s)", name);
				}
				else
				{
					/* add index string */
					proto_item_append_text(psf_item," (%s", val_to_str_ext_const(((guint32)(sod_index<<16)), &sod_index_names, "User Defined"));
					proto_item_append_text(psf_item,"_%02Xh", (idx-sod_index));
					if(sod_index == EPL_SOD_PDO_RX_MAPP || sod_index == EPL_SOD_PDO_TX_MAPP)
					{
						proto_item_append_text(psf_item,"_AU64)");
					}
					else
					{
						proto_item_append_text(psf_item,"_REC)");
					}
				}

				if (objectcnt < 8)
					col_append_fstr(pinfo->cinfo, COL_INFO, " (0x%04X", idx);
				else
					col_append_str(pinfo->cinfo, COL_INFO, ".");

				if (sod_index != error)
					idx = sod_index;

				dataoffset += 2;

				proto_item_append_text(psf_od_tree, " Idx: 0x%04X", idx);

				/* get subindex offset */
				subindex = tvb_get_guint8(tvb, dataoffset);
				subobj = subobject_lookup(obj, subindex);
				proto_item_append_text(psf_od_tree, " SubIdx: 0x%02X", subindex);
				/* get subindex string */
				sub_str = val_to_str_ext_const(idx, &sod_cmd_sub_str, "unknown");
				/* get string value */
				sub_val = str_to_val(sub_str, sod_cmd_sub_str_val,error);

				if(sub_val != error)
					idx = sub_val;

				if (subobj)
				{
					psf_item = proto_tree_add_item(psf_od_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, dataoffset, 1, ENC_LITTLE_ENDIAN);
					proto_item_append_text(psf_item, " (%s)", subobj->info.name);
				}
				/* if the subindex is a EPL_SOD_STORE_PARAM */
				else if(idx == EPL_SOD_STORE_PARAM && subindex <= 0x7F && subindex >= 0x04)
				{
					psf_item = proto_tree_add_item(psf_od_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, dataoffset, 1, ENC_LITTLE_ENDIAN);
					proto_item_append_text(psf_item, " (ManufacturerParam_%02Xh_U32)", subindex);
				}
				/* if the subindex is a EPL_SOD_RESTORE_PARAM */
				else if(idx == EPL_SOD_RESTORE_PARAM && subindex <= 0x7F && subindex >= 0x04)
				{
					psf_item = proto_tree_add_item(psf_od_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, dataoffset, 1, ENC_LITTLE_ENDIAN);
					proto_item_append_text(psf_item, " (ManufacturerParam_%02Xh_U32)", subindex);
				}
				/* if the subindex is a EPL_SOD_PDO_RX_MAPP */
				else if(idx == EPL_SOD_PDO_RX_MAPP && subindex >= 0x01 && subindex <= 0xfe)
				{
					psf_item = proto_tree_add_item(psf_od_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, dataoffset, 1, ENC_LITTLE_ENDIAN);
					proto_item_append_text(psf_item, " (ObjectMapping)");
				}
				/* if the subindex is a EPL_SOD_PDO_TX_MAPP */
				else if(idx == EPL_SOD_PDO_TX_MAPP && subindex >= 0x01 && subindex <= 0xfe)
				{
					psf_item = proto_tree_add_item(psf_od_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, dataoffset, 1, ENC_LITTLE_ENDIAN);
					proto_item_append_text(psf_item, " (ObjectMapping)");
				}
				/* if the subindex has the value 0x00 */
				else if(subindex == 0x00)
				{
					psf_item = proto_tree_add_item(psf_od_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, dataoffset, 1, ENC_LITTLE_ENDIAN);
					proto_item_append_text(psf_item, " (NumberOfEntries)");
				}
				/* subindex */
				else
				{
					psf_item = proto_tree_add_item(psf_od_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, dataoffset, 1, ENC_LITTLE_ENDIAN);
					proto_item_append_text(psf_item, " (%s)", val_to_str_ext_const((subindex | (idx << 16)), &sod_index_names, "User Defined"));
				}

				/* info text */
				if (objectcnt < 8)
				{
					if (nosub)
						/* no subindex */
						col_append_fstr(pinfo->cinfo, COL_INFO, ")");
					else
						col_append_fstr(pinfo->cinfo, COL_INFO, "/%d)", subindex);
				}


				dataoffset += 1;
				proto_tree_add_uint(psf_od_tree, hf_epl_asnd_sdo_cmd_data_padding, tvb, dataoffset, 1, padding);
				dataoffset += 1;
				objectcnt++;
			}

			/* size of embedded data */
			psf_item = proto_tree_add_uint_format(psf_od_tree, hf_epl_asnd_sdo_cmd_data_size, tvb, dataoffset, size, size, "Data size: %d byte", size);
			PROTO_ITEM_SET_GENERATED(psf_item);

			/* if the frame is a PDO Mapping and the subindex is bigger than 0x00 */
			if((idx == EPL_SOD_PDO_TX_MAPP && subindex > 0x00) ||(idx == EPL_SOD_PDO_RX_MAPP && subindex > 0x00))
			{
				wmem_array_t *mappings = idx == EPL_SOD_PDO_TX_MAPP ? convo->TPDO : convo->RPDO;

				dissect_object_mapping(convo->profiles.CN, mappings, epl_tree, tvb, pinfo->num, dataoffset, idx, subindex);
			}
			else /* dissect the payload */
			{
				dissect_epl_payload(psf_od_tree, tvb, pinfo, dataoffset, size, obj ? obj->info.type : NULL, EPL_ASND);
			}

			offset += datalength;

			/* calculating the remaining length, based on the current offset */
			remlength = (guint32)tvb_reported_length_remaining(tvb, offset);
		}

		col_append_fstr(pinfo->cinfo, COL_INFO, " (%d)", objectcnt);
	}
	else
	{
		/* response, no payload */
		col_append_str(pinfo->cinfo, COL_INFO, "Response");
	}
	return offset;
}

gint
dissect_epl_sdo_command_read_by_index(struct epl_convo *convo, proto_tree *epl_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, guint8 segmented, gboolean response, guint16 segment_size)
{
	gint size, payload_length;
	guint16 idx = 0x00;
	guint8 subindex = 0x00;
	guint32 fragmentId, frame;
	proto_item *psf_item, *cmd_payload;
	proto_tree *payload_tree;
	gboolean end_segment = FALSE;
	fragment_head *frag_msg = NULL;
	struct object *obj = NULL;
	struct subobject *subobj = NULL;
	struct read_req *req;
	const struct epl_datatype *type = NULL;

	/* get the current frame number */
	frame = pinfo->num;

	if (!response)
	{   /* request */
		const char *name;
		idx = tvb_get_letohs(tvb, offset);
		psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_index, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		obj = object_lookup(convo->profiles.CN, idx);

		name = obj ? obj->info.name
		           : val_to_str_ext_const(((guint32)(idx<<16)), &sod_index_names, "User Defined");
		proto_item_append_text(psf_item," (%s)", name);
		offset += 2;


		subindex = tvb_get_guint8(tvb, offset);
		psf_item = proto_tree_add_item(epl_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		subobj = subobject_lookup(obj, subindex);

		name = subobj ? subobj->info.name
		              : val_to_str_ext_const((subindex|(idx<<16)), &sod_index_names, "User Defined");
		proto_item_append_text(psf_item, " (%s)", name);

		offset += 1;

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s[%d]: (0x%04X/%d)",
						 val_to_str_ext(EPL_ASND_SDO_COMMAND_READ_BY_INDEX, &epl_sdo_asnd_commands_short_ext, "Command(%02X)"),
						 segment_size, idx, subindex);
		col_append_fstr(pinfo->cinfo, COL_INFO, " (%s", val_to_str_ext_const(((guint32) (idx << 16)), &sod_index_names, "User Defined"));
		col_append_fstr(pinfo->cinfo, COL_INFO, "/%s)",val_to_str_ext_const((subindex|(idx<<16)), &sod_index_names, "User Defined"));

		/* Cache object for read in next response */
		req = convo_read_req_set(convo, convo->seq_send);
		req->idx = idx;
		req->subindex = subindex;
		if (obj) {
			req->info = subobj ? &subobj->info : &obj->info;
			req->index_name = obj->info.name;
		} else {
			req->info = NULL;
			req->index_name = NULL;
		}
	}
	else
	{
		/* upload and no response */
		if(segmented > 0x01 && segment_size != 0)
		{
			/* get the fragmentId */
			fragmentId = (guint32)((((guint32)epl_segmentation.src)<<16)+epl_segmentation.dest);
			/* set the fragmented flag */
			pinfo->fragmented = TRUE;
			/* get payloade size */
			payload_length = tvb_reported_length_remaining(tvb, offset);
			/* if the frame is the last frame */
			if(segmented == EPL_ASND_SDO_CMD_SEGMENTATION_TRANSFER_COMPLETE)
				end_segment = TRUE;

			if(epl_asnd_sdo_reassembly_read.frame[epl_segmentation.recv][epl_segmentation.send] == 0x00 ||
				epl_asnd_sdo_reassembly_read.frame[epl_segmentation.recv][epl_segmentation.send] == frame)
			{
				if (epl_asnd_sdo_reassembly_read.frame[epl_segmentation.recv][epl_segmentation.send] == 0x00)
					count += 1;
				/* store the current frame and increase the counter */
				epl_asnd_sdo_reassembly_read.frame[epl_segmentation.recv][epl_segmentation.send] = frame;

				/* add the frame to reassembly_table */
				if (first_read)
				{
					frag_msg = fragment_add_seq_check(&epl_reassembly_table, tvb, offset, pinfo,
							fragmentId, NULL, 0, payload_length, end_segment ? FALSE : TRUE );
					fragment_add_seq_offset(&epl_reassembly_table, pinfo, fragmentId, NULL, count);

					first_read = FALSE;
				}
				else
				{
					frag_msg = fragment_add_seq_check(&epl_reassembly_table, tvb, offset, pinfo,
							fragmentId, NULL, count, payload_length, end_segment ? FALSE : TRUE );
				}
			}

			/* if the reassembly_table is not Null and the frame stored is the same as the current frame */
			if(frag_msg != NULL && (epl_asnd_sdo_reassembly_read.frame[epl_segmentation.recv][epl_segmentation.send] == frame))
			{
				if(end_segment || payload_length > 0)
				{
					cmd_payload = proto_tree_add_uint_format(epl_tree, hf_epl_asnd_sdo_cmd_reassembled, tvb, offset, payload_length,0,
															"Reassembled: %d bytes total (%d bytes in this frame)",frag_msg->len,payload_length);
					payload_tree = proto_item_add_subtree(cmd_payload, ett_epl_asnd_sdo_data_reassembled);
					/* add the reassembley fields */
					process_reassembled_data(tvb, 0, pinfo, "Reassembled Message", frag_msg, &epl_frag_items, NULL, payload_tree );
					proto_tree_add_uint_format_value(payload_tree, hf_epl_asnd_sdo_cmd_reassembled, tvb, 0, 0,
									payload_length, "%d bytes (over all fragments)", frag_msg->len);
					if (frag_msg->reassembled_in == frame)
						col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)" );
					/* reset memory */
					memset(&epl_asnd_sdo_reassembly_read.frame[epl_segmentation.recv], 0, sizeof(guint32) * EPL_MAX_SEQUENCE);
				}
				else
				{
					cmd_payload = proto_tree_add_uint_format(epl_tree, hf_epl_asnd_sdo_cmd_reassembled, tvb, offset, payload_length,0,
															"Reassembled: %d bytes total (%d bytes in this frame)",frag_msg->len,payload_length);
					payload_tree = proto_item_add_subtree(cmd_payload, ett_epl_asnd_sdo_data_reassembled);
					/* add reassemble field => Reassembled in: */
					process_reassembled_data(tvb, 0, pinfo, "Reassembled Message", frag_msg, &epl_frag_items, NULL, payload_tree );
				}

				first_read = TRUE;
				count = 0;
			}
		}
		/* response */
		col_append_str(pinfo->cinfo, COL_INFO, "Response");

		size = tvb_reported_length_remaining(tvb, offset);

		/* Did we register the read req? */

		if ((req = convo_read_req_get(convo, pinfo, convo->seq_send))) {
			proto_item *ti;
			ti = proto_tree_add_uint_format_value(epl_tree, hf_epl_asnd_sdo_cmd_data_index, tvb, 0, 0, req->idx, "%04X", req->idx);
			PROTO_ITEM_SET_GENERATED(ti);
			if (req->info)
			{
				proto_item_append_text (ti, " (%s)", req->index_name);
				type = req->info->type;
			}

			ti = proto_tree_add_uint_format_value(epl_tree, hf_epl_asnd_sdo_cmd_data_subindex, tvb, 0, 0, req->subindex, "%02X", req->subindex);
			PROTO_ITEM_SET_GENERATED(ti);

			if (req->info && req->info->name != req->index_name)
				proto_item_append_text (ti, " (%s)", req->info->name);

		}

		offset = dissect_epl_payload(epl_tree, tvb, pinfo, offset, size, type, EPL_ASND);
	}

	return offset;
}

/* User Access Table Checkers */
static gboolean epl_profile_uat_fld_fileopen_check_cb(void *, const char *, unsigned, const void *, const void *, char **);
static gboolean epl_uat_fld_cn_check_cb(void *, const char *, unsigned, const void *, const void *, char **);
static gboolean epl_uat_fld_uint16dec_check_cb(void *, const char *, unsigned, const void *, const void *, char **);
static gboolean epl_uat_fld_uint32hex_check_cb(void *, const char *, unsigned, const void *, const void *, char **);

/* DeviceType:Path User Access Table */
struct device_profile_uat_assoc {
	char *path;

	guint DeviceType;
	guint VendorId;
	guint ProductCode;
};

static uat_t *device_profile_uat = NULL;
static struct device_profile_uat_assoc *device_profile_list_uats = NULL;
static guint ndevice_profile_uat = 0;

static void *device_profile_uat_copy_cb(void *dst_, const void *src_, size_t len _U_);
static void device_profile_uat_free_cb(void *r);
static gboolean device_profile_uat_update_record(void *r, char **err);
static void device_profile_parse_uat(void);

UAT_DEC_CB_DEF(device_profile_list_uats, DeviceType, struct device_profile_uat_assoc)
UAT_HEX_CB_DEF(device_profile_list_uats, VendorId, struct device_profile_uat_assoc)
UAT_HEX_CB_DEF(device_profile_list_uats, ProductCode, struct device_profile_uat_assoc)
UAT_FILENAME_CB_DEF(device_profile_list_uats, path, struct device_profile_uat_assoc)

static uat_field_t device_profile_list_uats_flds[] = {
	UAT_FLD_CSTRING_OTHER(device_profile_list_uats, DeviceType, "DeviceType", epl_uat_fld_uint16dec_check_cb, "e.g. 401"),
	UAT_FLD_CSTRING_OTHER(device_profile_list_uats, VendorId, "VendorId", epl_uat_fld_uint32hex_check_cb, "e.g. DEADBEEF"),
	UAT_FLD_CSTRING_OTHER(device_profile_list_uats, ProductCode, "ProductCode", epl_uat_fld_uint32hex_check_cb, "e.g. 8BADFOOD"),

	UAT_FLD_FILENAME_OTHER(device_profile_list_uats, path, "Profile Path", epl_profile_uat_fld_fileopen_check_cb, "Path to the EDS" IF_LIBXML("/XDD/XDC")),

	UAT_END_FIELDS
};

/* NodeID:Path User Access Table */
struct nodeid_profile_uat_assoc {
	char *path;

	guint nodeid;
};

static uat_t *nodeid_profile_uat = NULL;
static struct nodeid_profile_uat_assoc *nodeid_profile_list_uats = NULL;
static guint nnodeid_profile_uat = 0;

static void *nodeid_profile_uat_copy_cb(void *dst_, const void *src_, size_t len _U_);
static void nodeid_profile_uat_free_cb(void *r);
static gboolean nodeid_profile_uat_update_record(void *r, char **err);
static void nodeid_profile_parse_uat(void);

UAT_DEC_CB_DEF(nodeid_profile_list_uats, nodeid, struct nodeid_profile_uat_assoc)
UAT_FILENAME_CB_DEF(nodeid_profile_list_uats, path, struct nodeid_profile_uat_assoc)

static uat_field_t nodeid_profile_list_uats_flds[] = {
	UAT_FLD_CSTRING_OTHER(nodeid_profile_list_uats, nodeid, "Node ID", epl_uat_fld_cn_check_cb, "e.g. 1"),

	UAT_FLD_FILENAME_OTHER(nodeid_profile_list_uats, path, "Profile Path", epl_profile_uat_fld_fileopen_check_cb, "Path to the EDS" IF_LIBXML("/XDD/XDC")),

	UAT_END_FIELDS
};


/* Register the protocol with Wireshark */
void
proto_register_epl(void)
{
	static hf_register_info hf[] = {
		/* Common data fields (same for all message types) */
		{ &hf_epl_mtyp,
			{ "MessageType", "epl-xdd.mtyp",
				FT_UINT8, BASE_DEC, VALS(mtyp_vals), 0x7F, NULL, HFILL }
		},
		{ &hf_epl_node,
			{ "Node", "epl-xdd.node",
				FT_UINT8, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_dest,
			{ "Destination", "epl-xdd.dest",
				FT_UINT8, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_src,
			{ "Source", "epl-xdd.src",
				FT_UINT8, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_payload_real,
			{ "Captured Size", "epl-xdd.payload.capture_size",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},

		/* SoC data fields*/
		{ &hf_epl_soc,
			{ "Flags", "epl-xdd.soc",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_epl_soc_mc,
			{ "MC (Multiplexed Cycle Completed)", "epl-xdd.soc.mc",
				FT_BOOLEAN, 8, NULL, EPL_SOC_MC_MASK, NULL, HFILL }
		},
		{ &hf_epl_soc_ps,
			{ "PS (Prescaled Slot)", "epl-xdd.soc.ps",
				FT_BOOLEAN, 8, NULL, EPL_SOC_PS_MASK, NULL, HFILL }
		},
		{ &hf_epl_soc_nettime,
			{ "NetTime", "epl-xdd.soc.nettime",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_epl_soc_relativetime,
			{ "RelativeTime", "epl-xdd.soc.relativetime",
				FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},

		/* PReq data fields*/
		{ &hf_epl_preq,
			{ "Flags", "epl-xdd.preq",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_epl_preq_ms,
			{ "MS (Multiplexed Slot)", "epl-xdd.preq.ms",
				FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }
		},
		{ &hf_epl_preq_ea,
			{ "EA (Exception Acknowledge)", "epl-xdd.preq.ea",
				FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
		},
		{ &hf_epl_preq_rd,
			{ "RD (Ready)", "epl-xdd.preq.rd",
				FT_BOOLEAN, 8, NULL, EPL_PDO_RD_MASK, NULL, HFILL }
		},
		{ &hf_epl_preq_pdov,
			{ "PDOVersion", "epl-xdd.preq.pdov",
				FT_UINT8, BASE_CUSTOM, CF_FUNC(elp_version), 0x00, NULL, HFILL }
		},
		{ &hf_epl_preq_size,
			{ "Size", "epl-xdd.preq.size",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},

		/* PRes data fields*/
		{ &hf_epl_pres_stat_ms,
			{ "NMTStatus", "epl-xdd.pres.stat",
				FT_UINT8, BASE_HEX, VALS(epl_nmt_ms_vals), 0x00, NULL, HFILL }
		},
		{ &hf_epl_pres_stat_cs,
			{ "NMTStatus", "epl-xdd.pres.stat",
				FT_UINT8, BASE_HEX, VALS(epl_nmt_cs_vals), 0x00, NULL, HFILL }
		},
		{ &hf_epl_pres,
			{ "Flags", "epl-xdd.pres",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_epl_pres_ms,
			{ "MS (Multiplexed Slot)", "epl-xdd.pres.ms",
				FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }
		},
		{ &hf_epl_pres_en,
			{ "EN (Exception New)", "epl-xdd.pres.en",
				FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
		},
		{ &hf_epl_pres_rd,
			{ "RD (Ready)", "epl-xdd.pres.rd",
				FT_BOOLEAN, 8, NULL, EPL_PDO_RD_MASK, NULL, HFILL }
		},
		{ &hf_epl_pres_pr,
			{ "PR (Priority)", "epl-xdd.pres.pr",
				FT_UINT8, BASE_DEC, VALS(epl_pr_vals), 0x38, NULL, HFILL }
		},
		{ &hf_epl_pres_rs,
			{ "RS (RequestToSend)", "epl-xdd.pres.rs",
				FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL }
		},
		{ &hf_epl_pres_pdov,
			{ "PDOVersion", "epl-xdd.pres.pdov",
				FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_pres_size,
			{ "Size", "epl-xdd.pres.size",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},

		/* SoA data fields*/
		{ &hf_epl_soa_stat_ms,
			{ "NMTStatus", "epl-xdd.soa.stat",
				FT_UINT8, BASE_HEX, VALS(epl_nmt_ms_vals), 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_stat_cs,
			{ "NMTStatus", "epl-xdd.soa.stat",
				FT_UINT8, BASE_HEX, VALS(epl_nmt_cs_vals), 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_ea,
			{ "EA (Exception Acknowledge)", "epl-xdd.soa.ea",
				FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
		},
		{ &hf_epl_soa_er,
			{ "ER (Exception Reset)", "epl-xdd.soa.er",
				FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }
		},
		{ &hf_epl_soa_svid,
			{ "RequestedServiceID", "epl-xdd.soa.svid",
				FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(soa_svid_vals), 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_svtg,
			{ "RequestedServiceTarget", "epl-xdd.soa.svtg",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_eplv,
			{ "EPLVersion", "epl-xdd.soa.eplv",
				FT_UINT8, BASE_CUSTOM, CF_FUNC(elp_version), 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_sync,
			{ "SyncControl", "epl-xdd.soa.sync",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_mac,
			{ "DestMacAddressValid", "epl-xdd.soa.adva",
				FT_BOOLEAN, 8, NULL, EPL_SOA_SYNC_MAC_VALID, NULL, HFILL }
		},

		{ &hf_epl_soa_pre_tm,
			{ "PResFallBackTimeoutValid", "epl-xdd.soa.tm",
				FT_BOOLEAN, 8, NULL, EPL_SOA_SYNC_PRES_TIMEOUT, NULL, HFILL }
		},
		{ &hf_epl_soa_mnd_sec,
			{ "SyncMNDelaySecondValid", "epl-xdd.soa.mnsc",
				FT_BOOLEAN, 8, NULL, EPL_SOA_SYNC_MND_SECOND, NULL, HFILL }
		},
		{ &hf_epl_soa_mnd_fst,
			{ "SyncMNDelayFirstValid", "epl-xdd.soa.mnft",
				FT_BOOLEAN, 8, NULL, EPL_SOA_SYNC_MND_FIRST, NULL, HFILL }
		},
		{ &hf_epl_soa_pre_sec,
			{ "PResTimeSecondValid", "epl-xdd.soa.prsc",
				FT_BOOLEAN, 8, NULL, EPL_SOA_SYNC_PRES_SECOND, NULL, HFILL }
		},
		{ &hf_epl_soa_pre_fst,
			{ "PResTimeFirstValid", "epl-xdd.soa.prft",
				FT_BOOLEAN, 8, NULL, EPL_SOA_SYNC_PRES_FIRST, NULL, HFILL }
		},
		{ &hf_epl_soa_pre_set ,
			{ "PResModeSet", "epl-xdd.soa.prmst",
				FT_BOOLEAN, 8, NULL, EPL_SOA_SYNC_PRES_SET, NULL, HFILL }
		},
		{ &hf_epl_soa_pre_res,
			{ "PResModeReset", "epl-xdd.soa.prmrst",
				FT_BOOLEAN, 8, NULL, EPL_SOA_SYNC_PRES_RESET, NULL, HFILL }
		},
		{ &hf_epl_soa_mac_end,
			{ "DestMacAddress", "epl-xdd.soa.adva.end",
				FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_epl_soa_pre_tm_end,
			{ "PResFallBackTimeoutValid", "epl-xdd.soa.tm.end",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_mnd_sec_end,
			{ "SyncMNDelaySecondValid", "epl-xdd.soa.mnsc.end",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_mnd_fst_end,
			{ "SyncMNDelayFirstValid", "epl-xdd.soa.mnft.end",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_pre_sec_end,
			{ "PResTimeSecondValid", "epl-xdd.soa.prsc.end",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_pre_fst_end,
			{ "PResTimeFirstValid", "epl-xdd.soa.prft.end",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_soa_dna_an_glb,
			{ "AN (Global)", "epl-xdd.soa.an.global",
				FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
		},
		{ &hf_epl_soa_dna_an_lcl,
			{ "AN (Local)", "epl-xdd.soa.an.local",
				FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
		},
		/* ASnd header */
		{ &hf_epl_asnd_svid,
			{ "Requested Service ID", "epl-xdd.asnd.svid",
				FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(asnd_svid_vals), 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_svtg,
			{ "Requested Service Target", "epl-xdd.asnd.svtg",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
#if 0
		{ &hf_epl_asnd_data,
			{ "Data", "epl-xdd.asnd.data",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
#endif

		/* ASnd-->IdentResponse */
		{ &hf_epl_asnd_identresponse_en,
			{ "EN (Exception New)", "epl-xdd.asnd.ires.en",
				FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_ec,
			{ "EC (Exception Clear)", "epl-xdd.asnd.ires.ec",
				FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_pr,
			{ "PR (Priority)", "epl-xdd.asnd.ires.pr",
				FT_UINT8, BASE_DEC, VALS(epl_pr_vals), 0x38, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_rs,
			{ "RS (RequestToSend)", "epl-xdd.asnd.ires.rs",
				FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_stat_ms,
			{ "NMTStatus", "epl-xdd.asnd.ires.state",
				FT_UINT8, BASE_HEX, VALS(epl_nmt_ms_vals), 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_stat_cs,
			{ "NMTStatus", "epl-xdd.asnd.ires.state",
				FT_UINT8, BASE_HEX, VALS(epl_nmt_cs_vals), 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_ever,
			{ "EPLVersion", "epl-xdd.asnd.ires.eplver",
				FT_UINT8, BASE_CUSTOM, CF_FUNC(elp_version), 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat,
			{ "FeatureFlags", "epl-xdd.asnd.ires.features",
				FT_UINT32, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit0,
			{ "Isochronous", "epl-xdd.asnd.ires.features.bit0",
				FT_BOOLEAN, 32, NULL, 0x0001, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit1,
			{ "SDO by UDP/IP", "epl-xdd.asnd.ires.features.bit1",
				FT_BOOLEAN, 32, NULL, 0x0002, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit2,
			{ "SDO by ASnd", "epl-xdd.asnd.ires.features.bit2",
				FT_BOOLEAN, 32, NULL, 0x0004, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit3,
			{ "SDO by PDO", "epl-xdd.asnd.ires.features.bit3",
				FT_BOOLEAN, 32, NULL, 0x0008, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit4,
			{ "NMT Info Services", "epl-xdd.asnd.ires.features.bit4",
				FT_BOOLEAN, 32, NULL, 0x0010, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit5,
			{ "Ext. NMT State Commands", "epl-xdd.asnd.ires.features.bit5",
				FT_BOOLEAN, 32, NULL, 0x0020, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit6,
			{ "Dynamic PDO Mapping", "epl-xdd.asnd.ires.features.bit6",
				FT_BOOLEAN, 32, NULL, 0x0040, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit7,
			{ "NMT Service by UDP/IP", "epl-xdd.asnd.ires.features.bit7",
				FT_BOOLEAN, 32, NULL, 0x0080, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit8,
			{ "Configuration Manager", "epl-xdd.asnd.ires.features.bit8",
				FT_BOOLEAN, 32, NULL, 0x0100, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit9,
			{ "Multiplexed Access", "epl-xdd.asnd.ires.features.bit9",
				FT_BOOLEAN, 32, NULL, 0x0200, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bitA,
			{ "NodeID setup by SW", "epl-xdd.asnd.ires.features.bitA",
				FT_BOOLEAN, 32, NULL, 0x0400, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bitB,
			{ "MN Basic Ethernet Mode", "epl-xdd.asnd.ires.features.bitB",
				FT_BOOLEAN, 32, NULL, 0x0800, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bitC,
			{ "Routing Type 1 Support", "epl-xdd.asnd.ires.features.bitC",
				FT_BOOLEAN, 32, NULL, 0x1000, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bitD,
			{ "Routing Type 2 Support", "epl-xdd.asnd.ires.features.bitD",
				FT_BOOLEAN, 32, NULL, 0x2000, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bitE,
			{ "SDO Read/Write All", "epl-xdd.asnd.ires.features.bitE",
				FT_BOOLEAN, 32, NULL, 0x4000, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bitF,
			{ "SDO Read/Write Multiple", "epl-xdd.asnd.ires.features.bitF",
				FT_BOOLEAN, 32, NULL, 0x8000, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit10,
			{ "Multiple-ASend Support", "epl-xdd.asnd.ires.features.bit10",
				FT_BOOLEAN, 32, NULL, 0x10000, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit11,
			{ "Ring Redundancy", "epl-xdd.asnd.ires.features.bit11",
				FT_BOOLEAN, 32, NULL, 0x20000, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit12,
			{ "PResChaining", "epl-xdd.asnd.ires.features.bit12",
				FT_BOOLEAN, 32, NULL, 0x40000, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit13,
			{ "Multiple PReq/PRes", "epl-xdd.asnd.ires.features.bit13",
				FT_BOOLEAN, 32, NULL, 0x80000, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_feat_bit14,
			{ "Dynamic Node Allocation", "epl-xdd.asnd.ires.features.bit14",
				FT_BOOLEAN, 32, NULL, 0x100000, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_mtu,
			{ "MTU", "epl-xdd.asnd.ires.mtu",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_pis,
			{ "PollInSize", "epl-xdd.asnd.ires.pollinsize",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_pos,
			{ "PollOutSize", "epl-xdd.asnd.ires.polloutsizes",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_rst,
			{ "ResponseTime", "epl-xdd.asnd.ires.resptime",
				FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_dt,
			{ "DeviceType", "epl-xdd.asnd.ires.devicetype",
				FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_profile,
			{ "Profile", "epl-xdd.asnd.ires.profile",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_profile_path,
			{ "Profile Path", "epl-xdd.asnd.ires.profilepath",
				FT_STRING, STR_UNICODE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_vid,
			{ "VendorId", "epl-xdd.asnd.ires.vendorid",
				FT_UINT32, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_productcode,
			{ "ProductCode", "epl-xdd.asnd.ires.productcode",
				FT_UINT32, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_rno,
			{ "RevisionNumber", "epl-xdd.asnd.ires.revisionno",
				FT_UINT32, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_sno,
			{ "SerialNumber", "epl-xdd.asnd.ires.serialno",
				FT_UINT32, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_vex1,
			{ "VendorSpecificExtension1", "epl-xdd.asnd.ires.vendorext1",
				FT_UINT64, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_vcd,
			{ "VerifyConfigurationDate", "epl-xdd.asnd.ires.confdate",
				FT_UINT32, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_vct,
			{ "VerifyConfigurationTime", "epl-xdd.asnd.ires.conftime",
				FT_UINT32, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_ad,
			{ "ApplicationSwDate", "epl-xdd.asnd.ires.appswdate",
				FT_UINT32, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_at,
			{ "ApplicationSwTime", "epl-xdd.asnd.ires.appswtime",
				FT_UINT32, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_ipa,
			{ "IPAddress", "epl-xdd.asnd.ires.ip",
				FT_IPv4, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_snm,
			{ "SubnetMask", "epl-xdd.asnd.ires.subnet",
				FT_IPv4, BASE_NETMASK, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_gtw,
			{ "DefaultGateway", "epl-xdd.asnd.ires.gateway",
				FT_IPv4, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_hn,
			{ "HostName", "epl-xdd.asnd.ires.hostname",
				FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_identresponse_vex2,
			{ "VendorSpecificExtension2", "epl-xdd.asnd.ires.vendorext2",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},

		/* ASnd-->StatusResponse */
		{ &hf_epl_asnd_statusresponse_en,
			{ "EN (Exception New)", "epl-xdd.asnd.sres.en",
				FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_ec,
			{ "EC (Exception Clear)", "epl-xdd.asnd.sres.ec",
				FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_pr,
			{ "PR (Priority)", "epl-xdd.asnd.sres.pr",
				FT_UINT8, BASE_DEC, VALS(epl_pr_vals), 0x38, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_rs,
			{ "RS (RequestToSend)", "epl-xdd.asnd.sres.rs",
				FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_stat_ms,
			{ "NMTStatus", "epl-xdd.asnd.sres.stat",
				FT_UINT8, BASE_HEX, VALS(epl_nmt_ms_vals), 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_stat_cs,
			{ "NMTStatus", "epl-xdd.asnd.sres.stat",
				FT_UINT8, BASE_HEX, VALS(epl_nmt_cs_vals), 0x00, NULL, HFILL }
		},
		/* ASnd-->SyncResponse */
		{ &hf_epl_asnd_syncResponse_sync,
			{ "SyncResponse", "epl-xdd.asnd.syncresponse.sync",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_syncResponse_fst_val,
			{ "PResTimeFirstValid", "epl-xdd.asnd.syncresponse.fst.val",
				FT_BOOLEAN, 8, NULL, EPL_ASND_SYNCRESPONSE_FST_VALID, NULL, HFILL }
		},
		{ &hf_epl_asnd_syncResponse_sec_val,
			{ "PResTimeSecondValid", "epl-xdd.asnd.syncresponse.sec.val",
				FT_BOOLEAN, 8, NULL, EPL_ASND_SYNCRESPONSE_SEC_VALID, NULL, HFILL }
		},
		{ &hf_epl_asnd_syncResponse_mode,
			{ "PResModeStatus", "epl-xdd.asnd.syncresponse.mode",
				FT_BOOLEAN, 8, NULL, EPL_ASND_SYNCRESPONSE_MODE, NULL, HFILL }
		},
		{ &hf_epl_asnd_syncResponse_latency,
			{ "Latency", "epl-xdd.asnd.syncresponse.latency",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_syncResponse_node,
			{ "SyncDelayStation", "epl-xdd.asnd.syncresponse.delay.station",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_syncResponse_delay,
			{ "SyncDelay", "epl-xdd.asnd.syncresponse.delay",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_syncResponse_pre_fst,
			{ "PResTimeFirst", "epl-xdd.asnd.syncresponse.pres.fst",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_syncResponse_pre_sec,
			{ "PResTimeSecond", "epl-xdd.asnd.syncresponse.pres.sec",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
#if 0
		{ &hf_epl_asnd_statusresponse_seb,
			{ "StaticErrorBitField", "epl-xdd.asnd.sres.seb",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
#endif

		/*StaticErrorBitField */
		{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit0,
			{ "Generic error", "epl-xdd.asnd.res.seb.bit0",
				FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit1,
			{ "Current", "epl-xdd.asnd.res.seb.bit1",
				FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit2,
			{ "Voltage", "epl-xdd.asnd.res.seb.bit2",
				FT_UINT8, BASE_DEC, NULL, 0x04, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit3,
			{ "Temperature", "epl-xdd.asnd.res.seb.bit3",
				FT_UINT8, BASE_DEC, NULL, 0x08, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit4,
			{ "Communication error", "epl-xdd.asnd.res.seb.bit4",
				FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit5,
			{ "Device Profile Spec", "epl-xdd.asnd.res.seb.bit5",
				FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_seb_err_errorregister_u8_bit7,
			{ "Manufacturer Spec", "epl-xdd.asnd.res.seb.bit7",
				FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_seb_devicespecific_err,
			{ "Device Profile Spec", "epl-xdd.asnd.res.seb.devicespecific_err",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},

#if 0
		{ &hf_epl_asnd_statusresponse_el,
			{ "ErrorCodesList", "epl-xdd.asnd.sres.el",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_el_entry,
			{ "Entry", "epl-xdd.asnd.sres.el.entry",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
#endif

		/*List of Errors/Events*/
		{ &hf_epl_asnd_statusresponse_el_entry_type,
			{ "Entry Type", "epl-xdd.asnd.sres.el.entry.type",
				FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_el_entry_type_profile,
			{ "Profile", "epl-xdd.asnd.sres.el.entry.type.profile",
				FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_el_entry_type_mode,
			{ "Mode", "epl-xdd.asnd.sres.el.entry.type.mode",
				FT_UINT16, BASE_DEC, NULL, 0x3000, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_el_entry_type_bit14,
			{ "Bit14", "epl-xdd.asnd.sres.el.entry.type.bit14",
				FT_UINT16, BASE_DEC, NULL, 0x4000, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_el_entry_type_bit15,
			{ "Bit15", "epl-xdd.asnd.sres.el.entry.type.bit15",
				FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_el_entry_code,
			{ "Error Code", "epl-xdd.asnd.sres.el.entry.code",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_el_entry_time,
			{ "Time Stamp", "epl-xdd.asnd.sres.el.entry.time",
				FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_statusresponse_el_entry_add,
			{ "Additional Information", "epl-xdd.asnd.sres.el.entry.add",
				FT_UINT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},


		/* ASnd-->NMTRequest */
		{ &hf_epl_asnd_nmtrequest_rcid,
			{ "NMTRequestedCommandID", "epl-xdd.asnd.nmtrequest.rcid",
				FT_UINT8, BASE_HEX_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtrequest_rct,
			{ "NMTRequestedCommandTarget", "epl-xdd.asnd.nmtrequest.rct",
				FT_UINT8, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtrequest_rcd,
			{ "NMTRequestedCommandData", "epl-xdd.asnd.nmtrequest.rcd",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},

		/* ASnd-->NMTCommand */
		{ &hf_epl_asnd_nmtcommand_cid,
			{ "NMTCommandId", "epl-xdd.asnd.nmtcommand.cid",
				FT_UINT8, BASE_HEX_DEC | BASE_EXT_STRING,
				&asnd_cid_vals_ext, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_resetnode_reason,
			{ "Reset Reason", "epl-xdd.asnd.nmtcommand.resetnode_reason",
				FT_UINT16, BASE_HEX | BASE_EXT_STRING,
				&errorcode_vals_ext, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_cdat,
			{ "NMTCommandData", "epl-xdd.asnd.nmtcommand.cdat",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},

		{ &hf_epl_asnd_nmtcommand_nmtnethostnameset_hn,
			{ "HostName", "epl-xdd.asnd.nmtcommand.nmtnethostnameset.hn",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtflusharpentry_nid,
			{ "NodeID", "epl-xdd.asnd.nmtcommand.nmtflusharpentry.nid",
				FT_UINT8, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtpublishtime_dt,
			{ "DateTime", "epl-xdd.asnd.nmtcommand.nmtpublishtime.dt",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna,
			{ "DNA", "epl-xdd.asnd.nmtcommand.dna",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_flags,
			{ "Valid flags", "epl-xdd.asnd.nmtcommand.dna.flags",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_ltv,
			{ "Lease time valid", "epl-xdd.asnd.nmtcommand.dna.ltv",
				FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_hpm,
			{ "Hub port enable mask valid", "epl-xdd.asnd.nmtcommand.dna.hpm",
				FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_nnn,
			{ "Set new node number", "epl-xdd.asnd.nmtcommand.dna.nnn",
				FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_mac,
			{ "Compare current MAC ID", "epl-xdd.asnd.nmtcommand.dna.mac",
				FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_cnn,
			{ "Compare current node number", "epl-xdd.asnd.nmtcommand.dna.cnn",
				FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_currmac,
			{ "Current MAC ID", "epl-xdd.asnd.nmtcommand.dna.currmac",
				FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_hubenmsk,
			{ "Hub port enable mask", "epl-xdd.asnd.nmtcommand.dna.hubenmsk",
				FT_UINT64, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_currnn,
			{ "Current node number", "epl-xdd.asnd.nmtcommand.dna.currnn",
				FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_newnn,
			{ "New node number", "epl-xdd.asnd.nmtcommand.dna.newnn",
				FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_nmtcommand_nmtdna_leasetime,
			{ "Lease Time", "epl-xdd.asnd.nmtcommand.dna.leasetime",
				FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},

		/* ASnd-->SDO */
		{ &hf_epl_asnd_sdo_seq,
			{ "Sequence Layer", "epl-xdd.asnd.sdo.seq",
				FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_seq_receive_sequence_number,
			{ "ReceiveSequenceNumber", "epl-xdd.asnd.sdo.seq.receive.sequence.number",
				FT_UINT8, BASE_DEC, NULL, 0xfc, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_seq_receive_con,
			{ "ReceiveCon", "epl-xdd.asnd.sdo.seq.receive.con",
				FT_UINT8, BASE_DEC,
				VALS(epl_sdo_receive_con_vals), 0x03, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_seq_send_sequence_number,
			{ "SendSequenceNumber", "epl-xdd.asnd.sdo.seq.send.sequence.number",
				FT_UINT8, BASE_DEC, NULL, 0xfc, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_seq_send_con,
			{ "SendCon", "epl-xdd.asnd.sdo.seq.send.con",
				FT_UINT8, BASE_DEC, VALS(epl_sdo_send_con_vals),
				0x03, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd,
			{ "Command Layer", "epl-xdd.asnd.sdo.cmd",
				FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_transaction_id,
			{ "SDO Transaction ID", "epl-xdd.asnd.sdo.cmd.transaction.id",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_response,
			{ "SDO Response", "epl-xdd.asnd.sdo.cmd.response",
				FT_UINT8, BASE_DEC,
				VALS(epl_sdo_asnd_cmd_response), 0x80, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_abort,
			{ "SDO Abort", "epl-xdd.asnd.sdo.cmd.abort",
				FT_UINT8, BASE_DEC,
				VALS(epl_sdo_asnd_cmd_abort), 0x40, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_sub_abort,
			{ "SDO Sub Transfer", "epl-xdd.asnd.sdo.cmd.sub.abort",
				FT_UINT8, BASE_DEC,
				VALS(epl_sdo_asnd_cmd_abort), 0x80, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_segmentation,
			{ "SDO Segmentation", "epl-xdd.asnd.sdo.cmd.segmentation",
				FT_UINT8, BASE_DEC,
				VALS(epl_sdo_asnd_cmd_segmentation), 0x30, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_command_id,
			{ "SDO Command ID", "epl-xdd.asnd.sdo.cmd.command.id",
				FT_UINT8, BASE_DEC | BASE_EXT_STRING,
				&epl_sdo_asnd_commands_ext, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_segment_size,
			{ "SDO Segment size", "epl-xdd.asnd.sdo.cmd.segment.size",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_data_size,
			{ "SDO Data size", "epl-xdd.asnd.sdo.cmd.data.size",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_data_padding,
			{ "SDO Data Padding", "epl-xdd.asnd.sdo.cmd.data.padding",
				FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_abort_code,
			{ "SDO Transfer Abort", "epl-xdd.asnd.sdo.cmd.abort.code",
				FT_UINT8, BASE_HEX | BASE_EXT_STRING,
				&sdo_cmd_abort_code_ext, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_data_index,
			{ "OD Index", "epl-xdd.asnd.sdo.cmd.data.index",
				FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_data_subindex,
			{ "OD SubIndex", "epl-xdd.asnd.sdo.cmd.data.subindex",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_data_mapping,
			{ "Mapping", "epl-xdd.asnd.sdo.cmd.data.mapping",
				FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_data_mapping_index,
			{ "Index", "epl-xdd.asnd.sdo.cmd.data.mapping.index",
				FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_data_mapping_subindex,
			{ "SubIndex", "epl-xdd.asnd.sdo.cmd.data.mapping.subindex",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_data_mapping_offset,
			{ "Offset", "epl-xdd.asnd.sdo.cmd.data.mapping.offset",
				FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_data_mapping_length,
			{ "Length", "epl-xdd.asnd.sdo.cmd.data.mapping.length",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_fragments,
			{ "Message fragments", "epl-xdd.asnd.sdo.cmd.fragments",
				FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_fragment,
			{ "Message fragment", "epl-xdd.asnd.sdo.cmd.fragment",
				FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_fragment_overlap,
			{ "Message fragment overlap", "epl-xdd.asnd.sdo.cmd.fragment.overlap",
				FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_fragment_overlap_conflicts,
			{ "Message fragment overlapping with conflicting data",
			"epl-xdd.asnd.sdo.cmd.fragment.overlap.conflicts",
				FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_fragment_multiple_tails,
			{ "Message has multiple tail fragments", "epl-xdd.asnd.sdo.cmd.fragment.multiple_tails",
				FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_fragment_too_long_fragment,
			{ "Message fragment too long", "epl-xdd.asnd.sdo.cmd.fragment.too_long_fragment",
				FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_fragment_error,
			{ "Message defragmentation error", "epl-xdd.asnd.sdo.cmd.fragment.error",
				FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_fragment_count,
			{ "Message fragment count", "epl-xdd.asnd.sdo.cmd.fragment.count",
				FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_asnd_sdo_cmd_reassembled,
			{ "Reassembled", "epl-xdd.asnd.sdo.cmd.reassembled",
				FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_reassembled_in,
			{ "Reassembled in", "epl-xdd.asnd.sdo.cmd.reassembled.in",
				FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_reassembled_length,
			{ "Reassembled length", "epl-xdd.asnd.sdo.cmd.reassembled.length",
				FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_reassembled_data,
			{ "Reassembled Data", "epl-xdd.asnd.sdo.cmd.reassembled.data",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},

		/* EPL Data types */
		{ &hf_epl_pdo,
			{ "PDO", "epl-xdd.pdo",
				FT_STRING, STR_ASCII, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_pdo_index,
			{ "Index", "epl-xdd.pdo.index",
				FT_UINT16, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_pdo_subindex,
			{ "SubIndex", "epl-xdd.pdo.subindex",
				FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_pdo_meta_info,
			{ "Meta Info", "epl-xdd.pdo.meta",
				FT_STRING, STR_UNICODE, NULL, 0x00, NULL, HFILL }
		},

		{ &hf_epl_od_boolean,
			{ "Data", "epl-xdd.od.data",
				FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_integer8,
			{ "Data", "epl-xdd.od.data",
				FT_INT8, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_integer16,
			{ "Data", "epl-xdd.od.data",
				FT_INT16, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_integer24,
			{ "Data", "epl-xdd.od.data",
				FT_INT24, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_integer32,
			{ "Data", "epl-xdd.od.data",
				FT_INT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_integer40,
			{ "Data", "epl-xdd.od.data",
				FT_INT40, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_integer48,
			{ "Data", "epl-xdd.od.data",
				FT_INT48, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_integer56,
			{ "Data", "epl-xdd.od.data",
				FT_INT56, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_integer64,
			{ "Data", "epl-xdd.od.data",
				FT_INT64, BASE_DEC, NULL, 0x00, NULL, HFILL }
		},

		{ &hf_epl_od_real32,
			{ "Data", "epl-xdd.od.data",
				FT_FLOAT, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_real64,
			{ "Data", "epl-xdd.od.data",
				FT_DOUBLE, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},

		{ SIZE_TO_UNSIGNED_HF(1),
			{ "Data", "epl-xdd.od.data",
				FT_UINT8, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ SIZE_TO_UNSIGNED_HF(2),
			{ "Data", "epl-xdd.od.data",
				FT_UINT16, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ SIZE_TO_UNSIGNED_HF(3),
			{ "Data", "epl-xdd.od.data",
				FT_UINT24, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ SIZE_TO_UNSIGNED_HF(4),
			{ "Data", "epl-xdd.od.data",
				FT_UINT32, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ SIZE_TO_UNSIGNED_HF(5),
			{ "Data", "epl-xdd.od.data",
				FT_UINT40, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ SIZE_TO_UNSIGNED_HF(6),
			{ "Data", "epl-xdd.od.data",
				FT_UINT48, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ SIZE_TO_UNSIGNED_HF(7),
			{ "Data", "epl-xdd.od.data",
				FT_UINT56, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},
		{ SIZE_TO_UNSIGNED_HF(8),
			{ "Data", "epl-xdd.od.data",
				FT_UINT64, BASE_DEC_HEX, NULL, 0x00, NULL, HFILL }
		},

		{ &hf_epl_od_visible_string,
			{ "Data", "epl-xdd.od.data",
				FT_STRING, STR_ASCII, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_octet_string,
			{ "Data", "epl-xdd.od.data",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_unicode_string,
			{ "Data", "epl-xdd.od.data",
				FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
#if 0
		{ &hf_epl_od_time_of_day, /* not 1:1 */
			{ "Data", "epl-xdd.od.data",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_time_difference, /* not 1:1 */
			{ "Data", "epl-xdd.od.data",
				FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
#endif
		{ &hf_epl_od_nettime,
			{ "Data", "epl-xdd.od.data",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_epl_od_domain,
			{ "Data", "epl-xdd.od.data",
				FT_BYTES, BASE_ALLOW_ZERO, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_mac,
			{ "Data", "epl-xdd.od.data",
				FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL }
		},
		{ &hf_epl_od_ipv4,
			{ "Data", "epl-xdd.od.data",
				FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_epl,
		&ett_epl_soc,
		&ett_epl_preq,
		&ett_epl_pres,
		&ett_epl_feat,
		&ett_epl_seb,
		&ett_epl_el,
		&ett_epl_el_entry,
		&ett_epl_el_entry_type,
		&ett_epl_sdo_entry_type,
		&ett_epl_sdo,
		&ett_epl_sdo_data,
		&ett_epl_asnd_sdo_cmd_data_mapping,
		&ett_epl_sdo_sequence_layer,
		&ett_epl_sdo_command_layer,
		&ett_epl_soa_sync,
		&ett_epl_asnd_sync,
		&ett_epl_fragment,
		&ett_epl_fragments,
		&ett_epl_asnd_sdo_data_reassembled,
		&ett_epl_asnd_nmt_dna,
	};

	static ei_register_info ei[] = {
		{ &ei_duplicated_frame,
			{ "epl-xdd.asnd.sdo.duplication", PI_PROTOCOL, PI_NOTE,
				"Duplicated Frame", EXPFILL }
		},
		{ &ei_recvseq_value,
			{ "epl-xdd.error.value.receive.sequence", PI_PROTOCOL, PI_ERROR,
				"Invalid Value for ReceiveSequenceNumber", EXPFILL }
		},
		{ &ei_sendseq_value,
			{ "epl-xdd.error.value.send.sequence", PI_PROTOCOL, PI_ERROR,
				"Invalid Value for SendSequenceNumber", EXPFILL }
		},
		{ &ei_recvcon_value,
			{ "epl-xdd.error.receive.connection", PI_PROTOCOL, PI_ERROR,
				"Invalid Value for ReceiveCon", EXPFILL }
		},
		{ &ei_sendcon_value,
			{ "epl-xdd.error.send.connection", PI_PROTOCOL, PI_ERROR,
				"Invalid Value for SendCon", EXPFILL }
		},
		{ &ei_real_length_differs,
			{ "epl-xdd.error.payload.length.differs", PI_PROTOCOL, PI_ERROR,
				"Captured length differs from header information", EXPFILL }
		}
	};

	module_t *epl_module;
	expert_module_t *expert_epl;

	/* Register the protocol name and description */
	proto_epl = proto_register_protocol("Ethernet POWERLINK+XDD", "EPL-XDD", "epl-xdd");

	/* subdissector code */
	heur_epl_subdissector_list = register_heur_dissector_list("epl-xdd", proto_epl);
	heur_epl_data_subdissector_list = register_heur_dissector_list("epl_xdd_data", proto_epl);
	epl_asnd_dissector_table = register_dissector_table("epl-xdd.asnd",
		"Manufacturer specific ASND service", proto_epl, FT_UINT8, BASE_DEC /*, DISSECTOR_TABLE_NOT_ALLOW_DUPLICATE*/);

	/* Registering protocol to be called by another dissector */
	epl_handle = register_dissector("epl-xdd", dissect_epl, proto_epl);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_epl, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	/* Register expert information field */
	expert_epl = expert_register_protocol ( proto_epl );
	expert_register_field_array ( expert_epl, ei, array_length (ei ) );

	/* register preferences */
	epl_module = prefs_register_protocol(proto_epl, NULL);

	prefs_register_bool_preference(epl_module, "show_soc_flags", "Show flags of SoC frame in Info column",
		"If you are capturing in networks with multiplexed or slow nodes, this can be useful", &show_soc_flags);

	prefs_register_bool_preference(epl_module, "show_duplicated_command_layer", "Show command-layer in duplicated frames",
		"For analysis purposes one might want to show the command layer even if the dissectore assumes a duplicated frame", &show_cmd_layer_for_duplicated);

	prefs_register_bool_preference(epl_module, "show_pdo_meta_info", "Show life times and origin PDO Tx/Rx params for PDO entries",
		"For analysis purposes one might want to see how long the current mapping has been active for and what OD write caused it", &show_pdo_meta_info);

#ifdef HAVE_LIBXML2
	prefs_register_bool_preference(epl_module, "read_xdc_for_mappings", "Read ObjectMappings from XDC",
		"If you want to parse the defaultValue (XDD) and actualValue (XDC) attributes for ObjectMappings in order to detect default PDO mappings, which may not be exchanged over SDO ", &read_xdc_for_mappings);
#endif /* HAVE_LIBXML2 */

	/* populate static address for convo */
	set_address(&convo_mac, AT_NONE, 0, NULL);

	/* init device profiles support */
	epl_profiles_by_device = wmem_map_new(wmem_epan_scope(), epl_g_int16_hash, epl_g_int16_equal);
	epl_profiles_by_nodeid = wmem_map_new(wmem_epan_scope(), epl_g_int8_hash,  epl_g_int8_equal);

#ifdef HAVE_LIBXML2
	xdd_init();
#endif /* HAVE_LIBXML2 */
	/* FIXME: where to call xdd_free? */
	eds_init();

	device_profile_uat = uat_new("Device-Specific Profiles",
			sizeof (struct device_profile_uat_assoc),
			"epl_device_profiles",     /* filename */
			TRUE,                      /* from_profile */
			&device_profile_list_uats, /* data_ptr */
			&ndevice_profile_uat,      /* numitems_ptr */
			UAT_AFFECTS_DISSECTION,    /* affects dissection of packets, but not set of named fields */
			NULL,                      /* Help section (currently a wiki page) */
			device_profile_uat_copy_cb,
			device_profile_uat_update_record,
			device_profile_uat_free_cb,
			device_profile_parse_uat,
			device_profile_list_uats_flds);

	prefs_register_uat_preference(epl_module, "epl_device_profiles",
			"Device-Specific Profiles",
			"Add vendor-provided EDS" IF_LIBXML("/XDD") " profiles here",
			device_profile_uat
			);


	/* TODO: clear nodeid profiles on file change? */
	nodeid_profile_uat = uat_new("NodeID-Specific Profiles",
			sizeof (struct nodeid_profile_uat_assoc),
			"epl_nodeid_profiles",     /* filename */
			TRUE,                      /* from_profile */
			&nodeid_profile_list_uats, /* data_ptr */
			&nnodeid_profile_uat,      /* numitems_ptr */
			UAT_AFFECTS_DISSECTION,    /* affects dissection of packets, but not set of named fields */
			NULL,                      /* Help section (currently a wiki page) */
			nodeid_profile_uat_copy_cb,
			nodeid_profile_uat_update_record,
			nodeid_profile_uat_free_cb,
			nodeid_profile_parse_uat,
			nodeid_profile_list_uats_flds);

	prefs_register_uat_preference(epl_module, "epl_nodeid_profiles",
			"Node-Specific Profiles",
			"Assign vendor-provided EDS" IF_LIBXML("/XDD") " profiles to CN IDs here",
			nodeid_profile_uat
			);

	/* tap-registration */
	/*  epl_tap = register_tap("epl-xdd");*/

	puts("Loading EPL+XDD plugin (built on " __DATE__ " " __TIME__ ")");
}

void
proto_reg_handoff_epl(void)
{
	dissector_handle_t epl_udp_handle = create_dissector_handle(dissect_epludp, proto_epl);

	dissector_add_uint("ethertype", ETHERTYPE_EPL_V2, epl_handle);
	dissector_add_uint("udp.port", UDP_PORT_EPL, epl_udp_handle);

	/* register frame init routine */
	register_init_routine( setup_dissector );
	register_cleanup_routine( cleanup_dissector );
}


static gboolean
epl_uat_fld_cn_check_cb(void *record _U_, const char *str, guint len _U_, const void *u1 _U_, const void *u2 _U_, char **err)
{
	char *endptr;
	/* No octals */
	unsigned long val = strtoul(str, &endptr, g_str_has_prefix(str, "0x") ? 16 : 10);
	if (!EPL_IS_CN_NODEID(val) || endptr != str + len)
	{
		*err = g_strdup("Invalid argument. Expected a Controlled Node ID ([1-239])");
		return FALSE;
	}

	return TRUE;
}

static gboolean
epl_uat_fld_uint16dec_check_cb(void *_record _U_, const char *str, guint len _U_, const void *chk_data _U_, const void *fld_data _U_, char **err)
{
	char *endptr;
	unsigned long val = strtoul(str, &endptr, 10);
	if (val > G_MAXUINT16 || endptr != str + len)
	{
		*err = g_strdup("Invalid argument. Expected a decimal between [0-65535]");
		return FALSE;
	}
	return TRUE;
}

static gboolean
epl_uat_fld_uint32hex_check_cb(void *_record _U_, const char *str, guint len _U_, const void *chk_data _U_, const void *fld_data _U_, char **err)
{
	char *endptr;
	unsigned long val = strtoul(str, &endptr, 16);
	if (val > G_MAXUINT32 || endptr != str + len)
	{
		*err = g_strdup("Invalid argument. Expected a hexadecimal between [0-ffffffff]");
		return FALSE;
	}
	return TRUE;
}

static gboolean
epl_profile_uat_fld_fileopen_check_cb(void *record _U_, const char *path, guint len, const void *chk_data _U_, const void *fld_data _U_, char **err)
{
	const char *supported = "Only" IF_LIBXML(" *.xdd, *.xdc and") " *.eds profiles supported.";
	ws_statb64 st;


	if (!path || !len)
	{
		*err = g_strdup("No filename given.");
		return FALSE;
	}

	if (ws_stat64(path, &st) != 0)
	{
		*err = g_strdup_printf("File '%s' does not exist or access was denied.", path);
		return FALSE;
	}


	if (g_str_has_suffix(path, ".eds"))
	{
		*err = NULL;
		return TRUE;
	}
	
	if (g_str_has_suffix(path, ".xdd") || g_str_has_suffix(path, ".xdc"))
	{
#ifdef HAVE_LIBXML2
		*err = NULL;
		return TRUE;
#else /* !HAVE_LIBXML2 */
		*err = g_strdup_printf("*.xdd and *.xdc support not compiled in. %s", supported);
		return FALSE;
#endif /* !HAVE_LIBXML2 */
	}

	*err = g_strdup(supported);
	return FALSE;
}


static void
reload_profiles(void *key _U_, void *value, void *user_data _U_)
{
	struct profile *head = (struct profile*)value, *curr;
	while ((curr = head))
	{
		head = head->next;
		profile_del(curr);
	}
}

static void
device_profile_parse_uat(void)
{
	guint i;
	struct profile *profile = NULL;
	wmem_map_foreach(epl_profiles_by_device, reload_profiles, NULL);

	/* PDO Mappings can have dangling pointers after a profile change
	 * so we reset the memory pool. As PDO Mappings are refereneced
	 * via Conversations, we need to fix up those too. This seems to be
	 * done automatically. XXX check if this is still case after refactoring
	 * in b54c43801112711dcba341f3eb4701678a0e1916 (v2.2.5)
	 */

	if (pdo_mapping_scope)
		wmem_free_all(pdo_mapping_scope);

	for (i = 0; i < ndevice_profile_uat; i++)
	{
		struct device_profile_uat_assoc *uat = &(device_profile_list_uats[i]);

		if (g_str_has_suffix(uat->path, ".eds")) {
			profile = profile_new(wmem_epan_scope());
			if (!eds_load(profile, uat->path))
			{
				profile_del(profile);
				profile = NULL;
			}
#ifdef HAVE_LIBXML2
		}
		else if (g_str_has_suffix(uat->path, ".xdd") || g_str_has_suffix(uat->path, ".xdc"))
		{
			profile = profile_new(wmem_epan_scope());
			if (!xdd_load(profile, uat->path))
			{
				profile_del(profile);
				profile = NULL;
			}
#endif /* HAVE_LIBXML2 */
		}

		if (profile)
		{
			struct profile *profile_head;
			if ((profile_head = wmem_map_lookup(epl_profiles_by_device, &profile->id)))
			{
				wmem_map_remove(epl_profiles_by_device, &profile_head->id);
				profile->next = profile_head;
			}

			profile->id = uat->DeviceType;
			profile->data = &profile->id;
			profile->VendorId = uat->VendorId;
			profile->ProductCode = uat->ProductCode;

			wmem_map_insert(epl_profiles_by_device, &profile->id, profile);
			profile->parent_map = epl_profiles_by_device;

			EPL_INFO("Loading %s\n", profile->path);
		}
		else
		{
			report_failure("Profile '%s' couldn't be parsed.", uat->path);
		}
	}
}

static gboolean
device_profile_uat_update_record(void *_record _U_, char **err _U_)
{
	return TRUE;
}

static void
device_profile_uat_free_cb(void *_r)
{
	struct device_profile_uat_assoc *r = (struct device_profile_uat_assoc *)_r;
	g_free(r->path);
}

static void*
device_profile_uat_copy_cb(void *dst_, const void *src_, size_t len _U_)
{
	const struct device_profile_uat_assoc *src = (const struct device_profile_uat_assoc *)src_;
	struct device_profile_uat_assoc       *dst = (struct device_profile_uat_assoc *)dst_;

	dst->path        = g_strdup(src->path);
	dst->DeviceType  = src->DeviceType;
	dst->VendorId    = src->VendorId;
	dst->ProductCode = src->ProductCode;

	return dst;
}

static void
nodeid_profile_parse_uat(void)
{
	guint i;
	struct profile *profile = NULL;
	wmem_map_foreach(epl_profiles_by_nodeid, reload_profiles, NULL);

	/* PDO Mappings can have dangling pointers after a profile change
	 * so we reset the memory pool. As PDO Mappings are refereneced
	 * via Conversations, we need to fix up those too. This seems to be
	 * done automatically. XXX check if this is still case after refactoring
	 * in b54c43801112711dcba341f3eb4701678a0e1916 (v2.2.5)
	 */

	if (pdo_mapping_scope)
		wmem_free_all(pdo_mapping_scope);

	for (i = 0; i < nnodeid_profile_uat; i++)
	{
		struct nodeid_profile_uat_assoc *uat = &(nodeid_profile_list_uats[i]);
		guint8 nodeid = uat->nodeid;

		if (wmem_map_lookup(epl_profiles_by_nodeid, &nodeid))
			continue;

		/* XXX Silently skipping might not be the best course of action */
		if (!EPL_IS_CN_NODEID(uat->nodeid))
			continue;

		if (g_str_has_suffix(uat->path, ".eds")) {
			profile = profile_new(wmem_epan_scope());
			if (!eds_load(profile, uat->path))
			{
				profile_del(profile);
				profile = NULL;
			}
#ifdef HAVE_LIBXML2
		}
		else if (g_str_has_suffix(uat->path, ".xdd") || g_str_has_suffix(uat->path, ".xdc"))
		{
			profile = profile_new(wmem_epan_scope());
			if (!xdd_load(profile, uat->path))
			{
				profile_del(profile);
				profile = NULL;
			}
#endif /* HAVE_LIBXML2 */
		}

		if (profile)
		{
			profile->nodeid = nodeid;
			profile->data = &profile->nodeid;

			wmem_map_insert(epl_profiles_by_nodeid, &profile->nodeid, profile);
			profile->parent_map = epl_profiles_by_nodeid;

			EPL_INFO("Loading %s\n", profile->path);
		}
		else
		{
			report_failure("Profile '%s' couldn't be parsed.", uat->path);
		}
	}
}


static gboolean
nodeid_profile_uat_update_record(void *_record _U_, char **err _U_)
{
	return TRUE;
}

static void
nodeid_profile_uat_free_cb(void *_r)
{
	struct nodeid_profile_uat_assoc *r = (struct nodeid_profile_uat_assoc *)_r;
	g_free(r->path);
}

static void*
nodeid_profile_uat_copy_cb(void *dst_, const void *src_, size_t len _U_)
{
	const struct nodeid_profile_uat_assoc *src = (const struct nodeid_profile_uat_assoc *)src_;
	struct nodeid_profile_uat_assoc       *dst = (struct nodeid_profile_uat_assoc *)dst_;

	dst->path   = g_strdup(src->path);
	dst->nodeid = src->nodeid;

	return dst;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
