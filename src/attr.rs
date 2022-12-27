// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer, NlasIterator},
    parsers::{parse_string, parse_u16, parse_u32, parse_u64, parse_u8},
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
const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
const NL80211_ATTR_MAX_NUM_SCAN_SSIDS: u16 = 43;
const NL80211_ATTR_GENERATION: u16 = 46;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_ATTR_MAX_SCAN_IE_LEN: u16 = 56;
const NL80211_ATTR_CIPHER_SUITES: u16 = 57;
const NL80211_ATTR_WIPHY_RETRY_SHORT: u16 = 61;
const NL80211_ATTR_WIPHY_RETRY_LONG: u16 = 62;
const NL80211_ATTR_WIPHY_FRAG_THRESHOLD: u16 = 63;
const NL80211_ATTR_WIPHY_RTS_THRESHOLD: u16 = 64;
const NL80211_ATTR_4ADDR: u16 = 83;
const NL80211_ATTR_MAX_NUM_PMKIDS: u16 = 86;
const NL80211_ATTR_WIPHY_COVERAGE_CLASS: u16 = 89;
const NL80211_ATTR_WIPHY_TX_POWER_LEVEL: u16 = 98;
const NL80211_ATTR_CONTROL_PORT_ETHERTYPE: u16 = 102;
const NL80211_ATTR_SUPPORT_IBSS_RSN: u16 = 104;
const NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS: u16 = 123;
const NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN: u16 = 124;
const NL80211_ATTR_SUPPORT_AP_UAPSD: u16 = 130;
const NL80211_ATTR_MAX_MATCH_SETS: u16 = 133;
const NL80211_ATTR_TDLS_SUPPORT: u16 = 139;
const NL80211_ATTR_TDLS_EXTERNAL_SETUP: u16 = 140;
const NL80211_ATTR_WDEV: u16 = 153;
const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
const NL80211_ATTR_CENTER_FREQ2: u16 = 161;
const NL80211_ATTR_TXQ_STATS: u16 = 265;
const NL80211_ATTR_WIPHY_FREQ_OFFSET: u16 = 290;
const NL80211_ATTR_MLO_LINKS: u16 = 312;
const NL80211_ATTR_MLO_LINK_ID: u16 = 313;

const ETH_ALEN: usize = 6;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nl80211Attr {
    WiPhy(u32),
    WiPhyName(String),
    IfIndex(u32),
    IfName(String),
    IfType(Nl80211InterfaceType),
    Mac([u8; ETH_ALEN]),
    MaxNumScanSSIDs(u8),
    Generation(u32),
    MaxScanIELen(u16),
    WiPhyRetryShort(u8),
    WiPhyRetryLong(u8),
    WiPhyFragThreshold(u32),
    WiPhyRTSThreshold(u32),
    Use4Addr(bool),
    WiPhyFreq(u32),
    WiPhyFreqOffset(u32),
    WiPhyChannelType(Nl80211WiPhyChannelType),
    ControlPortEtherType,
    SupportIBSSRSN,
    MaxNumSchedScanSSIDs(u8),
    MaxSchedScanIELen(u16),
    CipherSuites(Vec<Nl80211CipherSuite>),
    SupportAPUAPSD,
    MaxMatchSets(u8),
    TDLSSupport,
    TDLSExternalSetup,
    Wdev(u64),
    ChannelWidth(Nl80211ChannelWidth),
    CenterFreq1(u32),
    CenterFreq2(u32),
    MaxNumPMKIDs(u8),
    WiPhyCoverageClass(u8),
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
            | Self::ChannelWidth(_)
            | Self::WiPhyFragThreshold(_)
            | Self::WiPhyRTSThreshold(_) => 4,
            Self::Wdev(_) => 8,
            Self::IfName(ref s)
            | Self::Ssid(ref s)
            | Self::WiPhyName(ref s) => s.len() + 1,
            Self::Mac(_) => ETH_ALEN,
            Self::Use4Addr(_)
            | Self::WiPhyRetryShort(_)
            | Self::WiPhyRetryLong(_)
            | Self::WiPhyCoverageClass(_)
            | Self::MaxNumScanSSIDs(_)
            | Self::MaxNumSchedScanSSIDs(_)
            | Self::MaxMatchSets(_)
            | Self::MaxNumPMKIDs(_) => 1,
            Self::MaxScanIELen(_) | Self::MaxSchedScanIELen(_) => 2,
            Self::SupportIBSSRSN
            | Self::SupportAPUAPSD
            | Self::TDLSSupport
            | Self::TDLSExternalSetup
            | Self::ControlPortEtherType => 0,
            Self::TransmitQueueStats(ref nlas) => nlas.as_slice().buffer_len(),
            Self::MloLinks(ref links) => links.as_slice().buffer_len(),
            Self::CipherSuites(ref suites) => suites.len() * 4,
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
            Self::MaxNumScanSSIDs(_) => NL80211_ATTR_MAX_NUM_SCAN_SSIDS,
            Self::Generation(_) => NL80211_ATTR_GENERATION,
            Self::MaxScanIELen(_) => NL80211_ATTR_MAX_SCAN_IE_LEN,
            Self::WiPhyRetryShort(_) => NL80211_ATTR_WIPHY_RETRY_SHORT,
            Self::WiPhyRetryLong(_) => NL80211_ATTR_WIPHY_RETRY_LONG,
            Self::WiPhyFragThreshold(_) => NL80211_ATTR_WIPHY_FRAG_THRESHOLD,
            Self::WiPhyRTSThreshold(_) => NL80211_ATTR_WIPHY_RTS_THRESHOLD,
            Self::Use4Addr(_) => NL80211_ATTR_4ADDR,
            Self::WiPhyFreq(_) => NL80211_ATTR_WIPHY_FREQ,
            Self::WiPhyFreqOffset(_) => NL80211_ATTR_WIPHY_FREQ_OFFSET,
            Self::WiPhyChannelType(_) => NL80211_ATTR_WIPHY_CHANNEL_TYPE,
            Self::ControlPortEtherType => NL80211_ATTR_CONTROL_PORT_ETHERTYPE,
            Self::SupportIBSSRSN => NL80211_ATTR_SUPPORT_IBSS_RSN,
            Self::MaxNumSchedScanSSIDs(_) => {
                NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS
            }
            Self::MaxSchedScanIELen(_) => NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN,
            Self::CipherSuites(_) => NL80211_ATTR_CIPHER_SUITES,
            Self::SupportAPUAPSD => NL80211_ATTR_SUPPORT_AP_UAPSD,
            Self::MaxMatchSets(_) => NL80211_ATTR_MAX_MATCH_SETS,
            Self::TDLSSupport => NL80211_ATTR_TDLS_SUPPORT,
            Self::TDLSExternalSetup => NL80211_ATTR_TDLS_EXTERNAL_SETUP,
            Self::Wdev(_) => NL80211_ATTR_WDEV,
            Self::ChannelWidth(_) => NL80211_ATTR_CHANNEL_WIDTH,
            Self::CenterFreq1(_) => NL80211_ATTR_CENTER_FREQ1,
            Self::CenterFreq2(_) => NL80211_ATTR_CENTER_FREQ2,
            Self::MaxNumPMKIDs(_) => NL80211_ATTR_MAX_NUM_PMKIDS,
            Self::WiPhyCoverageClass(_) => NL80211_ATTR_WIPHY_COVERAGE_CLASS,
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
            | Self::WiPhyTxPowerLevel(d)
            | Self::WiPhyFragThreshold(d)
            | Self::WiPhyRTSThreshold(d) => NativeEndian::write_u32(buffer, *d),
            Self::Wdev(d) => NativeEndian::write_u64(buffer, *d),
            Self::IfType(d) => NativeEndian::write_u32(buffer, (*d).into()),
            Self::Mac(ref s) => buffer.copy_from_slice(s),
            Self::IfName(ref s)
            | Self::Ssid(ref s)
            | Self::WiPhyName(ref s) => {
                buffer[..s.len()].copy_from_slice(s.as_bytes());
                buffer[s.len()] = 0;
            }
            Self::WiPhyRetryShort(d)
            | Self::WiPhyRetryLong(d)
            | Self::WiPhyCoverageClass(d)
            | Self::MaxNumScanSSIDs(d)
            | Self::MaxNumSchedScanSSIDs(d)
            | Self::MaxMatchSets(d)
            | Self::MaxNumPMKIDs(d) => buffer[0] = *d,
            Self::MaxScanIELen(d) | Self::MaxSchedScanIELen(d) => {
                NativeEndian::write_u16(buffer, (*d).into())
            }
            Self::Use4Addr(d) => buffer[0] = *d as u8,
            Self::SupportIBSSRSN
            | Self::SupportAPUAPSD
            | Self::TDLSSupport
            | Self::TDLSExternalSetup
            | Self::ControlPortEtherType => {}
            Self::WiPhyChannelType(d) => {
                NativeEndian::write_u32(buffer, (*d).into())
            }
            Self::ChannelWidth(d) => {
                NativeEndian::write_u32(buffer, (*d).into())
            }
            Self::TransmitQueueStats(ref nlas) => nlas.as_slice().emit(buffer),
            Self::MloLinks(ref links) => links.as_slice().emit(buffer),
            Self::CipherSuites(ref suites) => {
                for (suite, mut buffer) in
                    suites.iter().zip(buffer.chunks_exact_mut(4))
                {
                    let value = (*suite).into();
                    NativeEndian::write_u32(&mut buffer, value);
                }
            }
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
            NL80211_ATTR_MAX_NUM_SCAN_SSIDS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_NUM_SCAN_SSIDS value {:?}",
                    payload
                );
                Self::MaxNumScanSSIDs(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_GENERATION => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_GENERATION value {:?}",
                    payload
                );
                Self::Generation(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_MAX_SCAN_IE_LEN => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_SCAN_IE_LEN value {:?}",
                    payload
                );
                Self::MaxScanIELen(parse_u16(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_RETRY_SHORT => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_RETRY_SHORT value {:?}",
                    payload
                );
                Self::WiPhyRetryShort(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_RETRY_LONG => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_RETRY_LONG value {:?}",
                    payload
                );
                Self::WiPhyRetryLong(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_FRAG_THRESHOLD => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_FRAG_THRESHOLD value {:?}",
                    payload
                );
                Self::WiPhyFragThreshold(parse_u32(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_RTS_THRESHOLD => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_RTS_THRESHOLD value {:?}",
                    payload
                );
                Self::WiPhyRTSThreshold(parse_u32(payload).context(err_msg)?)
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
            NL80211_ATTR_CONTROL_PORT_ETHERTYPE => Self::ControlPortEtherType,
            NL80211_ATTR_SUPPORT_IBSS_RSN => Self::SupportIBSSRSN,
            NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_NUM_SCHED_SCAN_SSIDS value {:?}",
                    payload
                );
                Self::MaxNumSchedScanSSIDs(
                    parse_u8(payload).context(err_msg)?.into(),
                )
            }
            NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_SCHED_SCAN_IE_LEN value {:?}",
                    payload
                );
                Self::MaxSchedScanIELen(
                    parse_u16(payload).context(err_msg)?.into(),
                )
            }
            NL80211_ATTR_SUPPORT_AP_UAPSD => Self::SupportAPUAPSD,
            NL80211_ATTR_MAX_MATCH_SETS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_MATCH_SETS value {:?}",
                    payload
                );
                Self::MaxMatchSets(parse_u8(payload).context(err_msg)?.into())
            }
            NL80211_ATTR_TDLS_SUPPORT => Self::TDLSSupport,
            NL80211_ATTR_TDLS_EXTERNAL_SETUP => Self::TDLSExternalSetup,
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
            NL80211_ATTR_MAX_NUM_PMKIDS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_MAX_NUM_PKMIDS value {:?}",
                    payload
                );
                Self::MaxNumPMKIDs(parse_u8(payload).context(err_msg)?)
            }
            NL80211_ATTR_WIPHY_COVERAGE_CLASS => {
                let err_msg = format!(
                    "Invalid NL80211_ATTR_WIPHY_COVERAGE_CLASS value {:?}",
                    payload
                );
                Self::WiPhyCoverageClass(parse_u8(payload).context(err_msg)?)
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
            NL80211_ATTR_CIPHER_SUITES => {
                let mut suites = vec![];
                for bytes in payload.chunks_exact(4) {
                    let value = parse_u32(bytes)?;
                    suites.push(value.into())
                }
                Self::CipherSuites(suites)
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

pub const CIPHER_SUITE_WEP40: u32 = 0x000FAC01;
pub const CIPHER_SUITE_TKIP: u32 = 0x000FAC02;
pub const CIPHER_SUITE_CCMP: u32 = 0x000FAC04;
pub const CIPHER_SUITE_WEP104: u32 = 0x000FAC05;
pub const CIPHER_SUITE_CMAC: u32 = 0x000FAC06;
pub const CIPHER_SUITE_GCMP128: u32 = 0x000FAC08;
pub const CIPHER_SUITE_GCMP256: u32 = 0x000FAC09;
pub const CIPHER_SUITE_CCMP256: u32 = 0x000FAC0A;
pub const CIPHER_SUITE_GMAC128: u32 = 0x000FAC0b;
pub const CIPHER_SUITE_GMAC256: u32 = 0x000FAC0c;
pub const CIPHER_SUITE_CMAC256: u32 = 0x000FAC0d;
pub const CIPHER_SUITE_SMS4: u32 = 0x00147201;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Nl80211CipherSuite {
    WEP40,
    TKIP,
    CCMP,
    WEP104,
    CMAC,
    GCMP128,
    GCMP256,
    CCMP256,
    GMAC128,
    GMAC256,
    CMAC256,
    SMS4,
    Other(u32),
}

impl From<u32> for Nl80211CipherSuite {
    fn from(value: u32) -> Self {
        match value {
            CIPHER_SUITE_WEP40 => Self::WEP40,
            CIPHER_SUITE_TKIP => Self::TKIP,
            CIPHER_SUITE_CCMP => Self::CCMP,
            CIPHER_SUITE_WEP104 => Self::WEP104,
            CIPHER_SUITE_CMAC => Self::CMAC,
            CIPHER_SUITE_GCMP128 => Self::GCMP128,
            CIPHER_SUITE_GCMP256 => Self::GCMP256,
            CIPHER_SUITE_CCMP256 => Self::CCMP256,
            CIPHER_SUITE_GMAC128 => Self::GMAC128,
            CIPHER_SUITE_GMAC256 => Self::GMAC256,
            CIPHER_SUITE_CMAC256 => Self::CMAC256,
            CIPHER_SUITE_SMS4 => Self::SMS4,
            x => Self::Other(x),
        }
    }
}

impl Into<u32> for Nl80211CipherSuite {
    fn into(self) -> u32 {
        match self {
            Self::WEP40 => CIPHER_SUITE_WEP40,
            Self::TKIP => CIPHER_SUITE_TKIP,
            Self::CCMP => CIPHER_SUITE_CCMP,
            Self::WEP104 => CIPHER_SUITE_WEP104,
            Self::CMAC => CIPHER_SUITE_CMAC,
            Self::GCMP128 => CIPHER_SUITE_GCMP128,
            Self::GCMP256 => CIPHER_SUITE_GCMP256,
            Self::CCMP256 => CIPHER_SUITE_CCMP256,
            Self::GMAC128 => CIPHER_SUITE_GMAC128,
            Self::GMAC256 => CIPHER_SUITE_GMAC256,
            Self::CMAC256 => CIPHER_SUITE_GMAC256,
            Self::SMS4 => CIPHER_SUITE_SMS4,
            Self::Other(x) => x,
        }
    }
}
