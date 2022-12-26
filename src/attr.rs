// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_string, parse_u32, parse_u64, parse_u8},
    DecodeError, Emitable, Parseable,
};

use crate::{
    channel::{Nl80211ChannelWidth, Nl80211WiPhyChannelType},
    iface::Nl80211InterfaceType,
    stats::Nl80211TransmitQueueStat,
};

const NL80211_ATTR_WIPHY: u16 = 1;
const NL80211_ATTR_WIPHY_NAME: u16 = 2;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_IFTYPE: u16 = 5;
const NL80211_ATTR_MAC: u16 = 6;
const NL80211_ATTR_KEY_DATA: u16 = 7;
const NL80211_ATTR_KEY_IDX: u16 = 8;
const NL80211_ATTR_KEY_CIPHER: u16 = 9;
const NL80211_ATTR_KEY_SEQ: u16 = 10;
const NL80211_ATTR_KEY_DEFAULT: u16 = 11;
const NL80211_ATTR_BEACON_INTERVAL: u16 = 12;
const NL80211_ATTR_DTIM_PERIOD: u16 = 13;
const NL80211_ATTR_BEACON_HEAD: u16 = 14;
const NL80211_ATTR_BEACON_TAIL: u16 = 15;
const NL80211_ATTR_STA_AID: u16 = 16;
const NL80211_ATTR_STA_FLAGS: u16 = 17;
const NL80211_ATTR_STA_LISTEN_INTERVAL: u16 = 18;
const NL80211_ATTR_STA_SUPPORTED_RATES: u16 = 19;
const NL80211_ATTR_STA_VLAN: u16 = 20;
const NL80211_ATTR_STA_INFO: u16 = 21;
const NL80211_ATTR_WIPHY_BANDS: u16 = 22;
const NL80211_ATTR_MNTR_FLAGS: u16 = 23;
const NL80211_ATTR_MESH_ID: u16 = 24;
const NL80211_ATTR_STA_PLINK_ACTION: u16 = 25;
const NL80211_ATTR_MPATH_NEXT_HOP: u16 = 26;
const NL80211_ATTR_MPATH_INFO: u16 = 27;
const NL80211_ATTR_BSS_CTS_PROT: u16 = 28;
const NL80211_ATTR_BSS_SHORT_PREAMBLE: u16 = 29;
const NL80211_ATTR_BSS_SHORT_SLOT_TIME: u16 = 30;
const NL80211_ATTR_HT_CAPABILITY: u16 = 31;
const NL80211_ATTR_SUPPORTED_IFTYPES: u16 = 32;
const NL80211_ATTR_REG_ALPHA2: u16 = 33;
const NL80211_ATTR_REG_RULES: u16 = 34;
const NL80211_ATTR_MESH_CONFIG: u16 = 35;
const NL80211_ATTR_BSS_BASIC_RATES: u16 = 36;
const NL80211_ATTR_WIPHY_TXQ_PARAMS: u16 = 37;
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
const NL80211_ATTR_KEY_DEFAULT_MGMT: u16 = 40;
const NL80211_ATTR_MGMT_SUBTYPE: u16 = 41;
const NL80211_ATTR_IE: u16 = 42;
const NL80211_ATTR_MAX_NUM_SCAN_SSIDS: u16 = 43;
const NL80211_ATTR_SCAN_FREQUENCIES: u16 = 44;
const NL80211_ATTR_SCAN_SSIDS: u16 = 45;
const NL80211_ATTR_GENERATION: u16 = 46;
const NL80211_ATTR_BSS: u16 = 47;
const NL80211_ATTR_REG_INITIATOR: u16 = 48;
const NL80211_ATTR_REG_TYPE: u16 = 49;
const NL80211_ATTR_SUPPORTED_COMMANDS: u16 = 50;
const NL80211_ATTR_FRAME: u16 = 51;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_ATTR_AUTH_TYPE: u16 = 53;
const NL80211_ATTR_REASON_CODE: u16 = 54;
const NL80211_ATTR_KEY_TYPE: u16 = 55;
const NL80211_ATTR_MAX_SCAN_IE_LEN: u16 = 56;
const NL80211_ATTR_CIPHER_SUITES: u16 = 57;
const NL80211_ATTR_FREQ_BEFORE: u16 = 58;
const NL80211_ATTR_FREQ_AFTER: u16 = 59;
const NL80211_ATTR_FREQ_FIXED: u16 = 60;
const NL80211_ATTR_WIPHY_RETRY_SHORT: u16 = 61;
const NL80211_ATTR_WIPHY_RETRY_LONG: u16 = 62;
const NL80211_ATTR_WIPHY_FRAG_THRESHOLD: u16 = 63;
const NL80211_ATTR_WIPHY_RTS_THRESHOLD: u16 = 64;
const NL80211_ATTR_TIMED_OUT: u16 = 65;
const NL80211_ATTR_USE_MFP: u16 = 66;
const NL80211_ATTR_STA_FLAGS2: u16 = 67;
const NL80211_ATTR_CONTROL_PORT: u16 = 68;
const NL80211_ATTR_TESTDATA: u16 = 69;
const NL80211_ATTR_PRIVACY: u16 = 70;
const NL80211_ATTR_DISCONNECTED_BY_AP: u16 = 71;
const NL80211_ATTR_STATUS_CODE: u16 = 72;
const NL80211_ATTR_CIPHER_SUITES_PAIRWISE: u16 = 73;
const NL80211_ATTR_CIPHER_SUITE_GROUP: u16 = 74;
const NL80211_ATTR_WPA_VERSIONS: u16 = 75;
const NL80211_ATTR_AKM_SUITES: u16 = 76;
const NL80211_ATTR_REQ_IE: u16 = 77;
const NL80211_ATTR_RESP_IE: u16 = 78;
const NL80211_ATTR_PREV_BSSID: u16 = 79;
const NL80211_ATTR_KEY: u16 = 80;
const NL80211_ATTR_KEYS: u16 = 81;
const NL80211_ATTR_PID: u16 = 82;
const NL80211_ATTR_4ADDR: u16 = 83;
const NL80211_ATTR_SURVEY_INFO: u16 = 84;
const NL80211_ATTR_PMKID: u16 = 85;
const NL80211_ATTR_MAX_NUM_PMKIDS: u16 = 86;
const NL80211_ATTR_DURATION: u16 = 87;
const NL80211_ATTR_COOKIE: u16 = 88;
const NL80211_ATTR_WIPHY_COVERAGE_CLASS: u16 = 89;
const NL80211_ATTR_TX_RATES: u16 = 90;
const NL80211_ATTR_FRAME_MATCH: u16 = 91;
const NL80211_ATTR_ACK: u16 = 92;
const NL80211_ATTR_PS_STATE: u16 = 93;
const NL80211_ATTR_CQM: u16 = 94;
const NL80211_ATTR_LOCAL_STATE_CHANGE: u16 = 95;
const NL80211_ATTR_AP_ISOLATE: u16 = 96;
const NL80211_ATTR_WIPHY_TX_POWER_SETTING: u16 = 97;
const NL80211_ATTR_WIPHY_TX_POWER_LEVEL: u16 = 98;
const NL80211_ATTR_TX_FRAME_TYPES: u16 = 99;
const NL80211_ATTR_RX_FRAME_TYPES: u16 = 100;
const NL80211_ATTR_FRAME_TYPE: u16 = 101;
const NL80211_ATTR_CONTROL_PORT_ETHERTYPE: u16 = 102;
const NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT: u16 = 103;
const NL80211_ATTR_SUPPORT_IBSS_RSN: u16 = 104;
const NL80211_ATTR_WIPHY_ANTENNA_TX: u16 = 105;
const NL80211_ATTR_WIPHY_ANTENNA_RX: u16 = 106;
const NL80211_ATTR_MCAST_RATE: u16 = 107;
const NL80211_ATTR_OFFCHANNEL_TX_OK: u16 = 108;
const NL80211_ATTR_BSS_HT_OPMODE: u16 = 109;
const NL80211_ATTR_KEY_DEFAULT_TYPES: u16 = 110;
const NL80211_ATTR_MAX_REMAIN_ON_CHANNEL_DURATION: u16 = 111;
const NL80211_ATTR_MESH_SETUP: u16 = 112;
const NL80211_ATTR_WIPHY_ANTENNA_AVAIL_TX: u16 = 113;
const NL80211_ATTR_WIPHY_ANTENNA_AVAIL_RX: u16 = 114;
const NL80211_ATTR_SUPPORT_MESH_AUTH: u16 = 115;
const NL80211_ATTR_STA_PLINK_STATE: u16 = 116;
const NL80211_ATTR_WOWLAN_TRIGGERS: u16 = 117;
const NL80211_ATTR_WOWLAN_TRIGGERS_SUPPORTED: u16 = 118;
const NL80211_ATTR_SCHED_SCAN_INTERVAL: u16 = 119;
const NL80211_ATTR_INTERFACE_COMBINATIONS: u16 = 120;
const NL80211_ATTR_SOFTWARE_IFTYPES: u16 = 121;
const NL80211_ATTR_REKEY_DATA: u16 = 122;
const NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS: u16 = 123;
const NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN: u16 = 124;
const NL80211_ATTR_SCAN_SUPP_RATES: u16 = 125;
const NL80211_ATTR_HIDDEN_SSID: u16 = 126;
const NL80211_ATTR_IE_PROBE_RESP: u16 = 127;
const NL80211_ATTR_IE_ASSOC_RESP: u16 = 128;
const NL80211_ATTR_STA_WME: u16 = 129;
const NL80211_ATTR_SUPPORT_AP_UAPSD: u16 = 130;
const NL80211_ATTR_ROAM_SUPPORT: u16 = 131;
const NL80211_ATTR_SCHED_SCAN_MATCH: u16 = 132;
const NL80211_ATTR_MAX_MATCH_SETS: u16 = 133;
const NL80211_ATTR_PMKSA_CANDIDATE: u16 = 134;
const NL80211_ATTR_TX_NO_CCK_RATE: u16 = 135;
const NL80211_ATTR_TDLS_ACTION: u16 = 136;
const NL80211_ATTR_TDLS_DIALOG_TOKEN: u16 = 137;
const NL80211_ATTR_TDLS_OPERATION: u16 = 138;
const NL80211_ATTR_TDLS_SUPPORT: u16 = 139;
const NL80211_ATTR_TDLS_EXTERNAL_SETUP: u16 = 140;
const NL80211_ATTR_DEVICE_AP_SME: u16 = 141;
const NL80211_ATTR_DONT_WAIT_FOR_ACK: u16 = 142;
const NL80211_ATTR_FEATURE_FLAGS: u16 = 143;
const NL80211_ATTR_PROBE_RESP_OFFLOAD: u16 = 144;
const NL80211_ATTR_PROBE_RESP: u16 = 145;
const NL80211_ATTR_DFS_REGION: u16 = 146;
const NL80211_ATTR_DISABLE_HT: u16 = 147;
const NL80211_ATTR_HT_CAPABILITY_MASK: u16 = 148;
const NL80211_ATTR_NOACK_MAP: u16 = 149;
const NL80211_ATTR_INACTIVITY_TIMEOUT: u16 = 150;
const NL80211_ATTR_RX_SIGNAL_DBM: u16 = 151;
const NL80211_ATTR_BG_SCAN_PERIOD: u16 = 152;
const NL80211_ATTR_WDEV: u16 = 153;
const NL80211_ATTR_USER_REG_HINT_TYPE: u16 = 154;
const NL80211_ATTR_CONN_FAILED_REASON: u16 = 155;
const NL80211_ATTR_AUTH_DATA: u16 = 156;
const NL80211_ATTR_VHT_CAPABILITY: u16 = 157;
const NL80211_ATTR_SCAN_FLAGS: u16 = 158;
const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
const NL80211_ATTR_CENTER_FREQ2: u16 = 161;
const NL80211_ATTR_P2P_CTWINDOW: u16 = 162;
const NL80211_ATTR_P2P_OPPPS: u16 = 163;
const NL80211_ATTR_LOCAL_MESH_POWER_MODE: u16 = 164;
const NL80211_ATTR_ACL_POLICY: u16 = 165;
const NL80211_ATTR_MAC_ADDRS: u16 = 166;
const NL80211_ATTR_MAC_ACL_MAX: u16 = 167;
const NL80211_ATTR_RADAR_EVENT: u16 = 168;
const NL80211_ATTR_EXT_CAPA: u16 = 169;
const NL80211_ATTR_EXT_CAPA_MASK: u16 = 170;
const NL80211_ATTR_STA_CAPABILITY: u16 = 171;
const NL80211_ATTR_STA_EXT_CAPABILITY: u16 = 172;
const NL80211_ATTR_PROTOCOL_FEATURES: u16 = 173;
const NL80211_ATTR_SPLIT_WIPHY_DUMP: u16 = 174;
const NL80211_ATTR_DISABLE_VHT: u16 = 175;
const NL80211_ATTR_VHT_CAPABILITY_MASK: u16 = 176;
const NL80211_ATTR_MDID: u16 = 177;
const NL80211_ATTR_IE_RIC: u16 = 178;
const NL80211_ATTR_CRIT_PROT_ID: u16 = 179;
const NL80211_ATTR_MAX_CRIT_PROT_DURATION: u16 = 180;
const NL80211_ATTR_PEER_AID: u16 = 181;
const NL80211_ATTR_COALESCE_RULE: u16 = 182;
const NL80211_ATTR_CH_SWITCH_COUNT: u16 = 183;
const NL80211_ATTR_CH_SWITCH_BLOCK_TX: u16 = 184;
const NL80211_ATTR_CSA_IES: u16 = 185;
const NL80211_ATTR_CNTDWN_OFFS_BEACON: u16 = 186;
const NL80211_ATTR_CNTDWN_OFFS_PRESP: u16 = 187;
const NL80211_ATTR_RXMGMT_FLAGS: u16 = 188;
const NL80211_ATTR_STA_SUPPORTED_CHANNELS: u16 = 189;
const NL80211_ATTR_STA_SUPPORTED_OPER_CLASSES: u16 = 190;
const NL80211_ATTR_HANDLE_DFS: u16 = 191;
const NL80211_ATTR_SUPPORT_5_MHZ: u16 = 192;
const NL80211_ATTR_SUPPORT_10_MHZ: u16 = 193;
const NL80211_ATTR_OPMODE_NOTIF: u16 = 194;
const NL80211_ATTR_VENDOR_ID: u16 = 195;
const NL80211_ATTR_VENDOR_SUBCMD: u16 = 196;
const NL80211_ATTR_VENDOR_DATA: u16 = 197;
const NL80211_ATTR_VENDOR_EVENTS: u16 = 198;
const NL80211_ATTR_QOS_MAP: u16 = 199;
const NL80211_ATTR_MAC_HINT: u16 = 200;
const NL80211_ATTR_WIPHY_FREQ_HINT: u16 = 201;
const NL80211_ATTR_MAX_AP_ASSOC_STA: u16 = 202;
const NL80211_ATTR_TDLS_PEER_CAPABILITY: u16 = 203;
const NL80211_ATTR_SOCKET_OWNER: u16 = 204;
const NL80211_ATTR_CSA_C_OFFSETS_TX: u16 = 205;
const NL80211_ATTR_MAX_CSA_COUNTERS: u16 = 206;
const NL80211_ATTR_TDLS_INITIATOR: u16 = 207;
const NL80211_ATTR_USE_RRM: u16 = 208;
const NL80211_ATTR_WIPHY_DYN_ACK: u16 = 209;
const NL80211_ATTR_TSID: u16 = 210;
const NL80211_ATTR_USER_PRIO: u16 = 211;
const NL80211_ATTR_ADMITTED_TIME: u16 = 212;
const NL80211_ATTR_SMPS_MODE: u16 = 213;
const NL80211_ATTR_OPER_CLASS: u16 = 214;
const NL80211_ATTR_MAC_MASK: u16 = 215;
const NL80211_ATTR_WIPHY_SELF_MANAGED_REG: u16 = 216;
const NL80211_ATTR_EXT_FEATURES: u16 = 217;
const NL80211_ATTR_SURVEY_RADIO_STATS: u16 = 218;
const NL80211_ATTR_NETNS_FD: u16 = 219;
const NL80211_ATTR_SCHED_SCAN_DELAY: u16 = 220;
const NL80211_ATTR_REG_INDOOR: u16 = 221;
const NL80211_ATTR_MAX_NUM_SCHED_SCAN_PLANS: u16 = 222;
const NL80211_ATTR_MAX_SCAN_PLAN_INTERVAL: u16 = 223;
const NL80211_ATTR_MAX_SCAN_PLAN_ITERATIONS: u16 = 224;
const NL80211_ATTR_SCHED_SCAN_PLANS: u16 = 225;
const NL80211_ATTR_PBSS: u16 = 226;
const NL80211_ATTR_BSS_SELECT: u16 = 227;
const NL80211_ATTR_STA_SUPPORT_P2P_PS: u16 = 228;
const NL80211_ATTR_PAD: u16 = 229;
const NL80211_ATTR_IFTYPE_EXT_CAPA: u16 = 230;
const NL80211_ATTR_MU_MIMO_GROUP_DATA: u16 = 231;
const NL80211_ATTR_MU_MIMO_FOLLOW_MAC_ADDR: u16 = 232;
const NL80211_ATTR_SCAN_START_TIME_TSF: u16 = 233;
const NL80211_ATTR_SCAN_START_TIME_TSF_BSSID: u16 = 234;
const NL80211_ATTR_MEASUREMENT_DURATION: u16 = 235;
const NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY: u16 = 236;
const NL80211_ATTR_MESH_PEER_AID: u16 = 237;
const NL80211_ATTR_NAN_MASTER_PREF: u16 = 238;
const NL80211_ATTR_BANDS: u16 = 239;
const NL80211_ATTR_NAN_FUNC: u16 = 240;
const NL80211_ATTR_NAN_MATCH: u16 = 241;
const NL80211_ATTR_FILS_KEK: u16 = 242;
const NL80211_ATTR_FILS_NONCES: u16 = 243;
const NL80211_ATTR_MULTICAST_TO_UNICAST_ENABLED: u16 = 244;
const NL80211_ATTR_BSSID: u16 = 245;
const NL80211_ATTR_SCHED_SCAN_RELATIVE_RSSI: u16 = 246;
const NL80211_ATTR_SCHED_SCAN_RSSI_ADJUST: u16 = 247;
const NL80211_ATTR_TIMEOUT_REASON: u16 = 248;
const NL80211_ATTR_FILS_ERP_USERNAME: u16 = 249;
const NL80211_ATTR_FILS_ERP_REALM: u16 = 250;
const NL80211_ATTR_FILS_ERP_NEXT_SEQ_NUM: u16 = 251;
const NL80211_ATTR_FILS_ERP_RRK: u16 = 252;
const NL80211_ATTR_FILS_CACHE_ID: u16 = 253;
const NL80211_ATTR_PMK: u16 = 254;
const NL80211_ATTR_SCHED_SCAN_MULTI: u16 = 255;
const NL80211_ATTR_SCHED_SCAN_MAX_REQS: u16 = 256;
const NL80211_ATTR_WANT_1X_4WAY_HS: u16 = 257;
const NL80211_ATTR_PMKR0_NAME: u16 = 258;
const NL80211_ATTR_PORT_AUTHORIZED: u16 = 259;
const NL80211_ATTR_EXTERNAL_AUTH_ACTION: u16 = 260;
const NL80211_ATTR_EXTERNAL_AUTH_SUPPORT: u16 = 261;
const NL80211_ATTR_NSS: u16 = 262;
const NL80211_ATTR_ACK_SIGNAL: u16 = 263;
const NL80211_ATTR_CONTROL_PORT_OVER_NL80211: u16 = 264;
const NL80211_ATTR_TXQ_STATS: u16 = 265;
const NL80211_ATTR_TXQ_LIMIT: u16 = 266;
const NL80211_ATTR_TXQ_MEMORY_LIMIT: u16 = 267;
const NL80211_ATTR_TXQ_QUANTUM: u16 = 268;
const NL80211_ATTR_HE_CAPABILITY: u16 = 269;
const NL80211_ATTR_FTM_RESPONDER: u16 = 270;
const NL80211_ATTR_FTM_RESPONDER_STATS: u16 = 271;
const NL80211_ATTR_TIMEOUT: u16 = 272;
const NL80211_ATTR_PEER_MEASUREMENTS: u16 = 273;
const NL80211_ATTR_AIRTIME_WEIGHT: u16 = 274;
const NL80211_ATTR_STA_TX_POWER_SETTING: u16 = 275;
const NL80211_ATTR_STA_TX_POWER: u16 = 276;
const NL80211_ATTR_SAE_PASSWORD: u16 = 277;
const NL80211_ATTR_TWT_RESPONDER: u16 = 278;
const NL80211_ATTR_HE_OBSS_PD: u16 = 279;
const NL80211_ATTR_WIPHY_EDMG_CHANNELS: u16 = 280;
const NL80211_ATTR_WIPHY_EDMG_BW_CONFIG: u16 = 281;
const NL80211_ATTR_VLAN_ID: u16 = 282;
const NL80211_ATTR_HE_BSS_COLOR: u16 = 283;
const NL80211_ATTR_IFTYPE_AKM_SUITES: u16 = 284;
const NL80211_ATTR_TID_CONFIG: u16 = 285;
const NL80211_ATTR_CONTROL_PORT_NO_PREAUTH: u16 = 286;
const NL80211_ATTR_PMK_LIFETIME: u16 = 287;
const NL80211_ATTR_PMK_REAUTH_THRESHOLD: u16 = 288;
const NL80211_ATTR_RECEIVE_MULTICAST: u16 = 289;
const NL80211_ATTR_WIPHY_FREQ_OFFSET: u16 = 290;
const NL80211_ATTR_CENTER_FREQ1_OFFSET: u16 = 291;
const NL80211_ATTR_SCAN_FREQ_KHZ: u16 = 292;
const NL80211_ATTR_HE_6GHZ_CAPABILITY: u16 = 293;
const NL80211_ATTR_FILS_DISCOVERY: u16 = 294;
const NL80211_ATTR_UNSOL_BCAST_PROBE_RESP: u16 = 295;
const NL80211_ATTR_S1G_CAPABILITY: u16 = 296;
const NL80211_ATTR_S1G_CAPABILITY_MASK: u16 = 297;
const NL80211_ATTR_SAE_PWE: u16 = 298;
const NL80211_ATTR_RECONNECT_REQUESTED: u16 = 299;
const NL80211_ATTR_SAR_SPEC: u16 = 300;
const NL80211_ATTR_DISABLE_HE: u16 = 301;
const NL80211_ATTR_OBSS_COLOR_BITMAP: u16 = 302;
const NL80211_ATTR_COLOR_CHANGE_COUNT: u16 = 303;
const NL80211_ATTR_COLOR_CHANGE_COLOR: u16 = 304;
const NL80211_ATTR_COLOR_CHANGE_ELEMS: u16 = 305;
const NL80211_ATTR_MBSSID_CONFIG: u16 = 306;
const NL80211_ATTR_MBSSID_ELEMS: u16 = 307;
const NL80211_ATTR_RADAR_BACKGROUND: u16 = 308;
const NL80211_ATTR_AP_SETTINGS_FLAGS: u16 = 309;
const NL80211_ATTR_EHT_CAPABILITY: u16 = 310;
const NL80211_ATTR_DISABLE_EHT: u16 = 311;
const NL80211_ATTR_MLO_LINKS: u16 = 312;
const NL80211_ATTR_MLO_LINK_ID: u16 = 313;
const NL80211_ATTR_MLD_ADDR: u16 = 314;
const NL80211_ATTR_MLO_SUPPORT: u16 = 315;
const NL80211_ATTR_MAX_NUM_AKM_SUITES: u16 = 316;
const NL80211_ATTR_EML_CAPABILITY: u16 = 317;
const NL80211_ATTR_MLD_CAPA_AND_OPS: u16 = 318;
const NL80211_ATTR_TX_HW_TIMESTAMP: u16 = 319;
const NL80211_ATTR_RX_HW_TIMESTAMP: u16 = 320;
const ETH_ALEN: usize = 6;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211Attr {
    WiPhy(u32),
    WiPhyName(String),
    IfIndex(u32),
    IfName(String),
    IfType(Nl80211InterfaceType),
    Mac([u8; ETH_ALEN]),
    Wdev(u64),
    Generation(u32),
    Use4Addr(bool),
    WiPhyFreq(u32),
    WiPhyFreqOffset(u32),
    WiPhyChannelType(Nl80211WiPhyChannelType),
    ChannelWidth(Nl80211ChannelWidth),
    CenterFreq1(u32),
    CenterFreq2(u32),
    WiPhyTxPowerLevel(u32),
    Ssid(String),
    TransmitQueueStats(Vec<Nl80211TransmitQueueStat>),
    MloLinks(Vec<Nl80211MloLink>),
    Other(DefaultNla),
}

impl Nla for Nl80211Attr {
    fn value_len(&self) -> usize {
        match self {
            Self::IfIndex(_)
            | Self::WiPhy(_)
            | Self::IfType(_)
            | Self::Generation(_)
            | Self::WiPhyFreq(_)
            | Self::WiPhyFreqOffset(_)
            | Self::WiPhyChannelType(_)
            | Self::CenterFreq1(_)
            | Self::CenterFreq2(_)
            | Self::WiPhyTxPowerLevel(_)
            | Self::ChannelWidth(_) => 4,
            Self::Wdev(_) => 8,
            Self::IfName(ref s)
            | Self::Ssid(ref s)
            | Self::WiPhyName(ref s) => s.len() + 1,
            Self::Mac(_) => ETH_ALEN,
            Self::Use4Addr(_) => 1,
            Self::TransmitQueueStats(ref nlas) => nlas.as_slice().buffer_len(),
            Self::MloLinks(ref links) => links.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::WiPhy(_) => NL80211_ATTR_WIPHY,
            Self::WiPhyName(_) => NL80211_ATTR_WIPHY_NAME,
            Self::IfIndex(_) => NL80211_ATTR_IFINDEX,
            Self::IfName(_) => NL80211_ATTR_IFNAME,
            Self::IfType(_) => NL80211_ATTR_IFTYPE,
            Self::Mac(_) => NL80211_ATTR_MAC,
            Self::Wdev(_) => NL80211_ATTR_WDEV,
            Self::Generation(_) => NL80211_ATTR_GENERATION,
            Self::Use4Addr(_) => NL80211_ATTR_4ADDR,
            Self::WiPhyFreq(_) => NL80211_ATTR_WIPHY_FREQ,
            Self::WiPhyFreqOffset(_) => NL80211_ATTR_WIPHY_FREQ_OFFSET,
            Self::WiPhyChannelType(_) => NL80211_ATTR_WIPHY_CHANNEL_TYPE,
            Self::ChannelWidth(_) => NL80211_ATTR_CHANNEL_WIDTH,
            Self::CenterFreq1(_) => NL80211_ATTR_CENTER_FREQ1,
            Self::CenterFreq2(_) => NL80211_ATTR_CENTER_FREQ2,
            Self::WiPhyTxPowerLevel(_) => NL80211_ATTR_WIPHY_TX_POWER_LEVEL,
            Self::Ssid(_) => NL80211_ATTR_SSID,
            Self::TransmitQueueStats(_) => NL80211_ATTR_TXQ_STATS,
            Self::MloLinks(_) => NL80211_ATTR_MLO_LINKS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::IfIndex(d)
            | Self::WiPhy(d)
            | Self::Generation(d)
            | Self::WiPhyFreq(d)
            | Self::WiPhyFreqOffset(d)
            | Self::CenterFreq1(d)
            | Self::CenterFreq2(d)
            | Self::WiPhyTxPowerLevel(d) => NativeEndian::write_u32(buffer, *d),
            Self::Wdev(d) => NativeEndian::write_u64(buffer, *d),
            Self::IfType(d) => NativeEndian::write_u32(buffer, (*d).into()),
            Self::Mac(ref s) => buffer.copy_from_slice(s),
            Self::IfName(ref s)
            | Self::Ssid(ref s)
            | Self::WiPhyName(ref s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Self::Use4Addr(d) => buffer[0] = *d as u8,
            Self::WiPhyChannelType(d) => {
                NativeEndian::write_u32(buffer, (*d).into())
            }
            Self::ChannelWidth(d) => {
                NativeEndian::write_u32(buffer, (*d).into())
            }
            Self::TransmitQueueStats(ref nlas) => nlas.as_slice().emit(buffer),
            Self::MloLinks(ref links) => links.as_slice().emit(buffer),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nl80211Attr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_ATTR_IFINDEX => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_IFINDEX value {:?}", payload);
                Self::IfIndex(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_WIPHY value {:?}", payload);
                Self::WiPhy(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_NAME => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_NAME value {:?}",
                    payload
                );
                Self::WiPhyName(parse_string(payload).context(err_msg)?)
            }
            NL80211_ATTR_IFNAME => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_IFNAME value {:?}", payload);
                Self::IfName(parse_string(payload).context(err_msg)?)
            }
            NL80211_ATTR_IFTYPE => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_IFTYPE value {:?}", payload);
                Self::IfType(parse_u32(payload).context(err_msg)?.into())
            }
            NL80211_ATTR_WDEV => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_WDEV value {:?}", payload);
                Self::Wdev(parse_u64(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAC => Self::Mac(if payload.len() == ETH_ALEN {
                let mut ret = [0u8; ETH_ALEN];
                ret.copy_from_slice(&payload[..ETH_ALEN]);
                ret
            } else {
                return Err(format!(
                    "Invalid length of NL80211_ATTR_MAC, expected length {} got {:?}",
                    ETH_ALEN, payload
                )
                .into());
            }),
            NL80211_ATTR_GENERATION => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_GENERATION value {:?}",
                    payload
                );
                Self::Generation(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_4ADDR => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_4ADDR value {:?}", payload);
                Self::Use4Addr(parse_u8(payload).context(err_msg)? > 0)
            }
            NL80211_ATTR_WIPHY_FREQ => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_FREQ value {:?}",
                    payload
                );
                Self::WiPhyFreq(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_FREQ_OFFSET => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_FREQ_OFFSET value {:?}",
                    payload
                );
                Self::WiPhyFreqOffset(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_CHANNEL_TYPE => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_CHANNEL_TYPE value {:?}",
                    payload
                );
                Self::WiPhyChannelType(
                    parse_u32(payload).context(err_msg)?.into(),
                )
            }
            NL80211_ATTR_CHANNEL_WIDTH => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CHANNEL_WIDTH value {:?}",
                    payload
                );
                Self::ChannelWidth(parse_u32(payload).context(err_msg)?.into())
            }
            NL80211_ATTR_CENTER_FREQ1 => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CENTER_FREQ1 value {:?}",
                    payload
                );
                Self::CenterFreq1(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_CENTER_FREQ2 => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_CENTER_FREQ2 value {:?}",
                    payload
                );
                Self::CenterFreq2(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_TX_POWER_LEVEL => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_TX_POWER_LEVEL value {:?}",
                    payload
                );
                Self::WiPhyTxPowerLevel(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_SSID => {
                let err_msg =
                    format!("Invalid NL80211_ATTR_SSID value {:?}", payload);
                Self::Ssid(parse_string(payload).context(err_msg)?)
            }
            NL80211_ATTR_TXQ_STATS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_TXQ_STATS value {:?}",
                    payload
                );
                let mut nlas = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    nlas.push(
                        Nl80211TransmitQueueStat::parse(nla)
                            .context(err_msg.clone())?,
                    );
                }
                Self::TransmitQueueStats(nlas)
            }
            NL80211_ATTR_MLO_LINKS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MLO_LINKS value {:?}",
                    payload
                );
                let mut links = Vec::new();
                for nla in NlasIterator::new(payload) {
                    let nla = &nla.context(err_msg.clone())?;
                    links.push(
                        Nl80211MloLink::parse(nla).context(err_msg.clone())?,
                    );
                }
                Self::MloLinks(links)
            }
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211MloLinkNla {
    Id(u8),
    Mac([u8; ETH_ALEN]),
    Other(DefaultNla),
}

impl Nla for Nl80211MloLinkNla {
    fn value_len(&self) -> usize {
        match self {
            Self::Id(_) => 1,
            Self::Mac(_) => ETH_ALEN,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Id(_) => NL80211_ATTR_MLO_LINK_ID,
            Self::Mac(_) => NL80211_ATTR_MAC,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Id(d) => buffer[0] = *d,
            Self::Mac(ref s) => buffer.copy_from_slice(s),
            Self::Other(ref attr) => attr.emit(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211MloLinkNla
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NL80211_ATTR_MLO_LINK_ID => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MLO_LINK_ID value {:?}",
                    payload
                );
                Self::Id(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAC => Self::Mac(if payload.len() == ETH_ALEN {
                let mut ret = [0u8; ETH_ALEN];
                ret.copy_from_slice(&payload[..ETH_ALEN]);
                ret
            } else {
                return Err(format!(
                    "Invalid length of NL80211_ATTR_MAC, expected length {} got {:?}",
                    ETH_ALEN, payload
                )
                .into());
            }),
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct Nl80211MloLink {
    pub id: u8,
    pub mac: [u8; ETH_ALEN],
}

impl Nla for Nl80211MloLink {
    fn value_len(&self) -> usize {
        Vec::<Nl80211MloLinkNla>::from(self).as_slice().buffer_len()
    }

    fn kind(&self) -> u16 {
        self.id as u16 + 1
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        Vec::<Nl80211MloLinkNla>::from(self).as_slice().emit(buffer)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for Nl80211MloLink
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let mut ret = Self::default();
        let payload = buf.value();
        let err_msg =
            format!("Invalid NL80211_ATTR_MLO_LINKS value {:?}", payload);
        for nla in NlasIterator::new(payload) {
            let nla = &nla.context(err_msg.clone())?;
            match Nl80211MloLinkNla::parse(nla).context(err_msg.clone())? {
                Nl80211MloLinkNla::Id(d) => ret.id = d,
                Nl80211MloLinkNla::Mac(s) => ret.mac = s,
                Nl80211MloLinkNla::Other(attr) => {
                    log::warn!(
                        "Got unsupported NL80211_ATTR_MLO_LINKS value {:?}",
                        attr
                    )
                }
            }
        }
        Ok(ret)
    }
}

impl From<&Nl80211MloLink> for Vec<Nl80211MloLinkNla> {
    fn from(link: &Nl80211MloLink) -> Self {
        vec![
            Nl80211MloLinkNla::Id(link.id),
            Nl80211MloLinkNla::Mac(link.mac),
        ]
    }
}
