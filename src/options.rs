use std::convert::TryFrom;
use std::fmt;

#[repr(u8)]
#[derive(PartialEq, Clone, Debug)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    ACK = 5,
    NAK = 6,
    Release = 7,
    Inform = 8,
    Unknown = 255,
}

impl TryFrom<u8> for MessageType {
    type Error = &'static str;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            1 => Ok(MessageType::Discover),
            2 => Ok(MessageType::Offer),
            3 => Ok(MessageType::Request),
            4 => Ok(MessageType::Decline),
            5 => Ok(MessageType::ACK),
            6 => Ok(MessageType::NAK),
            7 => Ok(MessageType::Release),
            8 => Ok(MessageType::Inform),
            _ => Err("message type out of range"),
        }
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                MessageType::Discover => "Discover",
                MessageType::Offer => "Offer",
                MessageType::Request => "Request",
                MessageType::Decline => "Decline",
                MessageType::ACK => "ACK",
                MessageType::NAK => "NAK",
                MessageType::Release => "Release",
                MessageType::Inform => "Inform",
                MessageType::Unknown => "Unknown",
            }
        )
    }
}

#[repr(u8)]
#[derive(PartialEq, Hash, Eq, Clone, Debug, Copy)]
pub enum OptionCode {
    End = 255,
    Pad = 0,
    SubnetMask = 1,
    TimeOffset = 2,
    Router = 3,
    TimeServer = 4,
    NameServer = 5,
    DomainNameServer = 6,
    LogServer = 7,
    CookieServer = 8,
    LPRServer = 9,
    ImpressServer = 10,
    ResourceLocationServer = 11,
    HostName = 12,
    BootFileSize = 13,
    MeritDumpFile = 14,
    DomainName = 15,
    SwapServer = 16,
    RootPath = 17,
    ExtensionsPath = 18,

    // IP Layer Parameters per Host
    IPForwardingEnableDisable = 19,
    NonLocalSourceRoutingEnableDisable = 20,
    PolicyFilter = 21,
    MaximumDatagramReassemblySize = 22,
    DefaultIPTimeToLive = 23,
    PathMTUAgingTimeout = 24,
    PathMTUPlateauTable = 25,

    // IP Layer Parameters per Interface
    InterfaceMTU = 26,
    AllSubnetsAreLocal = 27,
    BroadcastAddress = 28,
    PerformMaskDiscovery = 29,
    MaskSupplier = 30,
    PerformRouterDiscovery = 31,
    RouterSolicitationAddress = 32,
    StaticRoute = 33,

    // Link Layer Parameters per Interface
    TrailerEncapsulation = 34,
    ARPCacheTimeout = 35,
    EthernetEncapsulation = 36,

    // TCP Parameters
    TCPDefaultTTL = 37,
    TCPKeepaliveInterval = 38,
    TCPKeepaliveGarbage = 39,

    // Application and Service Parameters
    NetworkInformationServiceDomain = 40,
    NetworkInformationServers = 41,
    NetworkTimeProtocolServers = 42,
    VendorSpecificInformation = 43,
    NetBIOSOverTCPIPNameServer = 44,
    NetBIOSOverTCPIPDatagramDistributionServer = 45,
    NetBIOSOverTCPIPNodeType = 46,
    NetBIOSOverTCPIPScope = 47,
    XWindowSystemFontServer = 48,
    XWindowSystemDisplayManager = 49,
    NetworkInformationServicePlusDomain = 64,
    NetworkInformationServicePlusServers = 65,
    MobileIPHomeAgent = 68,
    SimpleMailTransportProtocol = 69,
    PostOfficeProtocolServer = 70,
    NetworkNewsTransportProtocol = 71,
    DefaultWorldWideWebServer = 72,
    DefaultFingerServer = 73,
    DefaultInternetRelayChatServer = 74,
    StreetTalkServer = 75,
    StreetTalkDirectoryAssistance = 76,

    RelayAgentInformation = 82,

    // DHCP Extensions
    RequestedIPAddress = 50,
    IPAddressLeaseTime = 51,
    Overload = 52,
    DHCPMessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    Message = 56,
    MaximumDHCPMessageSize = 57,
    RenewalTimeValue = 58,
    RebindingTimeValue = 59,
    VendorClassIdentifier = 60,
    ClientIdentifier = 61,

    TFTPServerName = 66,
    BootFileName = 67,

    UserClass = 77,

    ClientArchitecture = 93,

    TZPOSIXString = 100,
    TZDatabaseString = 101,

    ClasslessRouteFormat = 121,
}

impl TryFrom<u8> for OptionCode {
    type Error = &'static str;

    fn try_from(code: u8) -> Result<Self, Self::Error> {
        match code {
            255 => Ok(OptionCode::End),
            0 => Ok(OptionCode::Pad),
            1 => Ok(OptionCode::SubnetMask),
            2 => Ok(OptionCode::TimeOffset),
            3 => Ok(OptionCode::Router),
            4 => Ok(OptionCode::TimeServer),
            5 => Ok(OptionCode::NameServer),
            6 => Ok(OptionCode::DomainNameServer),
            7 => Ok(OptionCode::LogServer),
            8 => Ok(OptionCode::CookieServer),
            9 => Ok(OptionCode::LPRServer),
            10 => Ok(OptionCode::ImpressServer),
            11 => Ok(OptionCode::ResourceLocationServer),
            12 => Ok(OptionCode::HostName),
            13 => Ok(OptionCode::BootFileSize),
            14 => Ok(OptionCode::MeritDumpFile),
            15 => Ok(OptionCode::DomainName),
            16 => Ok(OptionCode::SwapServer),
            17 => Ok(OptionCode::RootPath),
            18 => Ok(OptionCode::ExtensionsPath),
            19 => Ok(OptionCode::IPForwardingEnableDisable),
            20 => Ok(OptionCode::NonLocalSourceRoutingEnableDisable),
            21 => Ok(OptionCode::PolicyFilter),
            22 => Ok(OptionCode::MaximumDatagramReassemblySize),
            23 => Ok(OptionCode::DefaultIPTimeToLive),
            24 => Ok(OptionCode::PathMTUAgingTimeout),
            25 => Ok(OptionCode::PathMTUPlateauTable),
            26 => Ok(OptionCode::InterfaceMTU),
            27 => Ok(OptionCode::AllSubnetsAreLocal),
            28 => Ok(OptionCode::BroadcastAddress),
            29 => Ok(OptionCode::PerformMaskDiscovery),
            30 => Ok(OptionCode::MaskSupplier),
            31 => Ok(OptionCode::PerformRouterDiscovery),
            32 => Ok(OptionCode::RouterSolicitationAddress),
            33 => Ok(OptionCode::StaticRoute),
            34 => Ok(OptionCode::TrailerEncapsulation),
            35 => Ok(OptionCode::ARPCacheTimeout),
            36 => Ok(OptionCode::EthernetEncapsulation),
            37 => Ok(OptionCode::TCPDefaultTTL),
            38 => Ok(OptionCode::TCPKeepaliveInterval),
            39 => Ok(OptionCode::TCPKeepaliveGarbage),
            40 => Ok(OptionCode::NetworkInformationServiceDomain),
            41 => Ok(OptionCode::NetworkInformationServers),
            42 => Ok(OptionCode::NetworkTimeProtocolServers),
            43 => Ok(OptionCode::VendorSpecificInformation),
            44 => Ok(OptionCode::NetBIOSOverTCPIPNameServer),
            45 => Ok(OptionCode::NetBIOSOverTCPIPDatagramDistributionServer),
            46 => Ok(OptionCode::NetBIOSOverTCPIPNodeType),
            47 => Ok(OptionCode::NetBIOSOverTCPIPScope),
            48 => Ok(OptionCode::XWindowSystemFontServer),
            49 => Ok(OptionCode::XWindowSystemDisplayManager),
            64 => Ok(OptionCode::NetworkInformationServicePlusDomain),
            65 => Ok(OptionCode::NetworkInformationServicePlusServers),
            68 => Ok(OptionCode::MobileIPHomeAgent),
            69 => Ok(OptionCode::SimpleMailTransportProtocol),
            70 => Ok(OptionCode::PostOfficeProtocolServer),
            71 => Ok(OptionCode::NetworkNewsTransportProtocol),
            72 => Ok(OptionCode::DefaultWorldWideWebServer),
            73 => Ok(OptionCode::DefaultFingerServer),
            74 => Ok(OptionCode::DefaultInternetRelayChatServer),
            75 => Ok(OptionCode::StreetTalkServer),
            76 => Ok(OptionCode::StreetTalkDirectoryAssistance),
            82 => Ok(OptionCode::RelayAgentInformation),
            50 => Ok(OptionCode::RequestedIPAddress),
            51 => Ok(OptionCode::IPAddressLeaseTime),
            52 => Ok(OptionCode::Overload),
            53 => Ok(OptionCode::DHCPMessageType),
            54 => Ok(OptionCode::ServerIdentifier),
            55 => Ok(OptionCode::ParameterRequestList),
            56 => Ok(OptionCode::Message),
            57 => Ok(OptionCode::MaximumDHCPMessageSize),
            58 => Ok(OptionCode::RenewalTimeValue),
            59 => Ok(OptionCode::RebindingTimeValue),
            60 => Ok(OptionCode::VendorClassIdentifier),
            61 => Ok(OptionCode::ClientIdentifier),
            66 => Ok(OptionCode::TFTPServerName),
            67 => Ok(OptionCode::BootFileName),
            77 => Ok(OptionCode::UserClass),
            93 => Ok(OptionCode::ClientArchitecture),
            100 => Ok(OptionCode::TZPOSIXString),
            101 => Ok(OptionCode::TZDatabaseString),
            121 => Ok(OptionCode::ClasslessRouteFormat),
            _ => Err("option code out of range"),
        }
    }
}

impl fmt::Display for OptionCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                OptionCode::Pad => "Pad",
                OptionCode::SubnetMask => "SubnetMask",
                OptionCode::TimeOffset => "TimeOffset",
                OptionCode::Router => "Router",
                OptionCode::TimeServer => "TimeServer",
                OptionCode::NameServer => "NameServer",
                OptionCode::DomainNameServer => "DomainNameServer",
                OptionCode::LogServer => "LogServer",
                OptionCode::CookieServer => "CookieServer",
                OptionCode::LPRServer => "LPRServer",
                OptionCode::ImpressServer => "ImpressServer",
                OptionCode::ResourceLocationServer => "ResourceLocationServer",
                OptionCode::HostName => "HostName",
                OptionCode::BootFileSize => "BootFileSize",
                OptionCode::MeritDumpFile => "MeritDumpFile",
                OptionCode::DomainName => "DomainName",
                OptionCode::SwapServer => "SwapServer",
                OptionCode::RootPath => "RootPath",
                OptionCode::ExtensionsPath => "ExtensionsPath",
                OptionCode::IPForwardingEnableDisable => "IPForwardingEnableDisable",
                OptionCode::NonLocalSourceRoutingEnableDisable =>
                    "NonLocalSourceRoutingEnableDisable",
                OptionCode::PolicyFilter => "PolicyFilter",
                OptionCode::MaximumDatagramReassemblySize => "MaximumDatagramReassemblySize",
                OptionCode::DefaultIPTimeToLive => "DefaultIPTimeToLive",
                OptionCode::PathMTUAgingTimeout => "PathMTUAgingTimeout",
                OptionCode::PathMTUPlateauTable => "PathMTUPlateauTable",
                OptionCode::InterfaceMTU => "InterfaceMTU",
                OptionCode::AllSubnetsAreLocal => "AllSubnetsAreLocal",
                OptionCode::BroadcastAddress => "BroadcastAddress",
                OptionCode::PerformMaskDiscovery => "PerformMaskDiscovery",
                OptionCode::MaskSupplier => "MaskSupplier",
                OptionCode::PerformRouterDiscovery => "PerformRouterDiscovery",
                OptionCode::RouterSolicitationAddress => "RouterSolicitationAddress",
                OptionCode::StaticRoute => "StaticRoute",
                OptionCode::TrailerEncapsulation => "TrailerEncapsulation",
                OptionCode::ARPCacheTimeout => "ARPCacheTimeout",
                OptionCode::EthernetEncapsulation => "EthernetEncapsulation",
                OptionCode::TCPDefaultTTL => "TCPDefaultTTL",
                OptionCode::TCPKeepaliveInterval => "TCPKeepaliveInterval",
                OptionCode::TCPKeepaliveGarbage => "TCPKeepaliveGarbage",
                OptionCode::NetworkInformationServiceDomain => "NetworkInformationServiceDomain",
                OptionCode::NetworkInformationServers => "NetworkInformationServers",
                OptionCode::NetworkTimeProtocolServers => "NetworkTimeProtocolServers",
                OptionCode::VendorSpecificInformation => "VendorSpecificInformation",
                OptionCode::NetBIOSOverTCPIPNameServer => "NetBIOSOverTCPIPNameServer",
                OptionCode::NetBIOSOverTCPIPDatagramDistributionServer =>
                    "NetBIOSOverTCPIPDatagramDistributionServer",
                OptionCode::NetBIOSOverTCPIPNodeType => "NetBIOSOverTCPIPNodeType",
                OptionCode::NetBIOSOverTCPIPScope => "NetBIOSOverTCPIPScope",
                OptionCode::XWindowSystemFontServer => "XWindowSystemFontServer",
                OptionCode::XWindowSystemDisplayManager => "XWindowSystemDisplayManager",
                OptionCode::NetworkInformationServicePlusDomain =>
                    "NetworkInformationServicePlusDomain",
                OptionCode::NetworkInformationServicePlusServers =>
                    "NetworkInformationServicePlusServers",
                OptionCode::MobileIPHomeAgent => "MobileIPHomeAgent",
                OptionCode::SimpleMailTransportProtocol => "SimpleMailTransportProtocol",
                OptionCode::PostOfficeProtocolServer => "PostOfficeProtocolServer",
                OptionCode::NetworkNewsTransportProtocol => "NetworkNewsTransportProtocol",
                OptionCode::DefaultWorldWideWebServer => "DefaultWorldWideWebServer",
                OptionCode::DefaultFingerServer => "DefaultFingerServer",
                OptionCode::DefaultInternetRelayChatServer => "DefaultInternetRelayChatServer",
                OptionCode::StreetTalkServer => "StreetTalkServer",
                OptionCode::StreetTalkDirectoryAssistance => "StreetTalkDirectoryAssistance",
                OptionCode::RelayAgentInformation => "RelayAgentInformation",
                OptionCode::RequestedIPAddress => "RequestedIPAddress",
                OptionCode::IPAddressLeaseTime => "IPAddressLeaseTime",
                OptionCode::Overload => "Overload",
                OptionCode::DHCPMessageType => "DHCPMessageType",
                OptionCode::ServerIdentifier => "ServerIdentifier",
                OptionCode::ParameterRequestList => "ParameterRequestList",
                OptionCode::Message => "Message",
                OptionCode::MaximumDHCPMessageSize => "MaximumDHCPMessageSize",
                OptionCode::RenewalTimeValue => "RenewalTimeValue",
                OptionCode::RebindingTimeValue => "RebindingTimeValue",
                OptionCode::VendorClassIdentifier => "VendorClassIdentifier",
                OptionCode::ClientIdentifier => "ClientIdentifier",
                OptionCode::TFTPServerName => "TFTPServerName",
                OptionCode::BootFileName => "BootFileName",
                OptionCode::UserClass => "UserClass",
                OptionCode::ClientArchitecture => "ClientArchitecture",
                OptionCode::TZPOSIXString => "TZPOSIXString",
                OptionCode::TZDatabaseString => "TZDatabaseString",
                OptionCode::ClasslessRouteFormat => "ClasslessRouteFormat",
                OptionCode::End => "End",
            }
        )
    }
}
