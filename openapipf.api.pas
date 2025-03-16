unit openapipf.api;

{$I mormot.defines.inc}

interface

{
  -------------------------------------------------------------------
  PFSENSE REST API DOCUMENTATION client as TOpenapipfClient class

  Generated 13 Mar 2025 by igor via mopenapi - DO NOT MODIFY BY HAND!
  -------------------------------------------------------------------
}

uses
  classes,
  sysutils,
  mormot.core.base,
  mormot.core.unicode,
  mormot.core.text,
  mormot.core.buffers,
  mormot.core.datetime,
  mormot.core.rtti,
  mormot.core.json,
  mormot.core.variants,
  mormot.net.client;

type

{ ************ Enumerations and Sets }

  TEnumOpenapipf1 = (
    eoNone, eo2048, eo3072, eo4096, eoCustom, eoEc256, eoEc384);
  TEnumOpenapipf2 = (
    eo2None, eo2Active, eo2Disabled);
  TEnumOpenapipf3 = (
    eo3None, eo3PhpCommand, eo3Servicerestart, eo3Shellcommand, eo3Xmlrpcservicerestart);
  TEnumOpenapipf4 = (
    eo4None, eo41, eo4157, eo4161, eo4162, eo4163, eo4164, eo4165);
  TEnumOpenapipf5 = (
    eo5None, eo51, eo5HttpsCoreThermoIo, eo5HttpsMyFuturehostingCom, eo5HttpsPortalNexcessNet);
  TEnumOpenapipf6 = (
    eo6None, eo61, eo6KimsufiCa, eo6KimsufiEu, eo6OvhCa, eo6OvhEu, eo6RunaboveCa,
    eo6SoyoustartCa, eo6SoyoustartEu);
  TEnumOpenapipf7 = (
    eo7None, eo7Disable, eo7Enable);
  TEnumOpenapipf8 = (
    eo8None, eo8One, eo8Subtree);
  TEnumOpenapipf9 = (
    eo9None, eo9SSLTLSEncrypted, eo9STARTTLSEncrypt, eo9StandardTCP);
  TEnumOpenapipf10 = (
    eo10None, eo10CHAPMD5, eo10MSCHAPv1, eo10MSCHAPv2, eo10PAP);
  TEnumOpenapipf11 = (
    eo11None, eo11Ldap, eo11Radius);
  TEnumOpenapipf12 = (
    eo12None, eo12Auto, eo12Off, eo12On);
  TEnumOpenapipf13 = (
    eo13None, eo131, eo134, eo136);
  TEnumOpenapipf14 = (
    eo14None, eo14Client, eo14Config, eo14Database, eo14Default, eo14Dispatch,
    eo14Dnssec, eo14General, eo14LameServers, eo14Network, eo14Notify,
    eo14Queries, eo14Resolver, eo14Security, eo14Unmatched, eo14Update,
    eo14XferIn, eo14XferOut);
  TEnumOpenapipf14Set = set of TEnumOpenapipf14;
  TEnumOpenapipf15 = (
    eo15None, eo15Critical, eo15Debug1, eo15Debug3, eo15Debug5, eo15Dynamic,
    eo15Error, eo15Info, eo15Notice, eo15Warning);
  TEnumOpenapipf16 = (
    eo16None, eo16Http, eo16Https);
  TEnumOpenapipf17 = (
    eo17None, eo17Auto, eo17Disabled, eo17Manual);
  TEnumOpenapipf18 = (
    eo18None, eo18Forward, eo18Master, eo18Redirect, eo18Slave);
  TEnumOpenapipf19 = (
    eo19None, eo19A, eo19AAAA, eo19CNAME, eo19LOC, eo19MX, eo19NS, eo19PTR,
    eo19SPF, eo19SRV, eo19TXT);
  TEnumOpenapipf20 = (
    eo20None, eo20Server, eo20User);
  TEnumOpenapipf21 = (
    eo21None, eo21ECDSA, eo21RSA);
  TEnumOpenapipf22 = (
    eo22None, eo22High, eo22Legacy, eo22Low);
  TEnumOpenapipf23 = (
    eo23None, eo23Existing, eo23Internal);
  TEnumOpenapipf24 = (
    eo24None, eo24Class, eo24Enabled);
  TEnumOpenapipf25 = (
    eo25None, eo25Isc, eo25Kea);
  TEnumOpenapipf26 = (
    eo26None, eo26Boolean, eo26IpAddress, eo26SignedInteger16, eo26SignedInteger32,
    eo26SignedInteger8, eo26String, eo26Text, eo26UnsignedInteger16, eo26UnsignedInteger32,
    eo26UnsignedInteger8);
  TEnumOpenapipf27 = (
    eo27None, eo27Allow, eo27AllowSnoop, eo27Deny, eo27DenyNonlocal, eo27Refuse,
    eo27RefuseNonlocal);
  TEnumOpenapipf28 = (
    eo28None, eo28PostValidator, eo28PreValidator);
  TEnumOpenapipf29 = (
    eo29None, eo29Deny, eo29Inform, eo29InformDeny, eo29Nodefault, eo29Redirect,
    eo29Refuse, eo29Static, eo29Transparent, eo29Typetransparent);
  TEnumOpenapipf30 = (
    eo30None, eo30LOGIN, eo30PLAIN);
  TEnumOpenapipf31 = (
    eo31None, eo31Host, eo31Network, eo31Port);
  TEnumOpenapipf32 = (
    eo32None, eo32Any, eo32In, eo32Out);
  TEnumOpenapipf33 = (
    eo33None, eo33Althost, eo33Any, eo33Dataconv, eo33Echorep, eo33Echoreq,
    eo33Inforep, eo33Inforeq, eo33Ipv6Here, eo33Ipv6Where, eo33Maskrep,
    eo33Maskreq, eo33Mobredir, eo33Mobregrep, eo33Mobregreq, eo33Paramprob,
    eo33Photuris, eo33Redir, eo33Routeradv, eo33Routersol, eo33Skip, eo33Squench,
    eo33Timerep, eo33Timereq, eo33Timex, eo33Trace, eo33Unreach);
  TEnumOpenapipf33Set = set of TEnumOpenapipf33;
  TEnumOpenapipf34 = (
    eo34None, eo34Inet, eo34Inet46, eo34Inet6);
  TEnumOpenapipf35 = (
    eo35None, eo35Ah, eo35Carp, eo35Esp, eo35Gre, eo35Icmp, eo35Igmp, eo35Ipv6,
    eo35Ospf, eo35Pfsync, eo35Pim, eo35Tcp, eo35TcpUdp, eo35Udp);
  TEnumOpenapipf36 = (
    eo36None, eo36KeepState, eo36None2, eo36SloppyState, eo36SynproxyState);
  TEnumOpenapipf37 = (
    eo37None, eo37Ack, eo37Cwr, eo37Ece, eo37Fin, eo37Psh, eo37Rst, eo37Syn,
    eo37Urg);
  TEnumOpenapipf37Set = set of TEnumOpenapipf37;
  TEnumOpenapipf38 = (
    eo38None, eo38Block, eo38Pass, eo38Reject);
  TEnumOpenapipf39 = (
    eo39None, eo391, eo39Leastconn, eo39Roundrobin, eo39Source, eo39StaticRr,
    eo39Uri);
  TEnumOpenapipf40 = (
    eo40None, eo40Basic, eo40ESMTP, eo40HTTP, eo40LDAP, eo40MySQL, eo40PostgreSQL,
    eo40Redis, eo40SMTP, eo40SSL, eo40None10);
  TEnumOpenapipf41 = (
    eo41None, eo411, eo41Alert, eo41Crit, eo41Debug, eo41Dontlog, eo41Emerg,
    eo41Err, eo41Info, eo41Notice, eo41Warning);
  TEnumOpenapipf42 = (
    eo42None, eo42DELETE, eo42GET, eo42HEAD, eo42OPTIONS, eo42POST, eo42PUT,
    eo42TRACE);
  TEnumOpenapipf43 = (
    eo43None, eo43InsertOnly, eo43InsertOnlySilent, eo43Passive, eo43PassiveSessionPrefix,
    eo43PassiveSilent, eo43Reset, eo43SessionPrefix, eo43Set, eo43SetSilent);
  TEnumOpenapipf44 = (
    eo44None, eo44None1, eo44StickCookieValue, eo44StickRdpCookie, eo44StickSourceipv4,
    eo44StickSourceipv6, eo44StickSslsessionid);
  TEnumOpenapipf45 = (
    eo45None, eo45Backendservercount, eo45Custom, eo45HostContains, eo45HostEndsWith,
    eo45HostMatches, eo45HostRegex, eo45HostStartsWith, eo45PathContains,
    eo45PathDir, eo45PathEndsWith, eo45PathMatches, eo45PathRegex, eo45PathStartsWith,
    eo45SourceIp, eo45SslCCaCommonname, eo45SslCVerify, eo45SslCVerifyCode,
    eo45SslSniContains, eo45SslSniEndsWith, eo45SslSniMatches, eo45SslSniRegex,
    eo45SslSniStartsWith, eo45TrafficIsHttp, eo45TrafficIsSsl, eo45UrlParameter);
  TEnumOpenapipf46 = (
    eo46None, eo46Custom, eo46HttpAfterResponseAddHeader, eo46HttpAfterResponseDelHeader,
    eo46HttpAfterResponseReplaceHeader, eo46HttpAfterResponseReplaceValue,
    eo46HttpAfterResponseSetHeader, eo46HttpAfterResponseSetStatus, eo46HttpRequestAddHeader,
    eo46HttpRequestAllow, eo46HttpRequestAuth, eo46HttpRequestDelHeader,
    eo46HttpRequestDeny, eo46HttpRequestLua, eo46HttpRequestRedirect, eo46HttpRequestReplaceHeader,
    eo46HttpRequestReplacePath, eo46HttpRequestReplaceValue, eo46HttpRequestSetHeader,
    eo46HttpRequestSetMethod, eo46HttpRequestSetPath, eo46HttpRequestSetQuery,
    eo46HttpRequestSetUri, eo46HttpRequestTarpit, eo46HttpRequestUseService,
    eo46HttpResponseAddHeader, eo46HttpResponseAllow, eo46HttpResponseDelHeader,
    eo46HttpResponseDeny, eo46HttpResponseLua, eo46HttpResponseReplaceHeader,
    eo46HttpResponseReplaceValue, eo46HttpResponseSetHeader, eo46HttpResponseSetStatus,
    eo46TcpRequestConnectionAccept, eo46TcpRequestConnectionReject, eo46TcpRequestContentAccept,
    eo46TcpRequestContentLua, eo46TcpRequestContentReject, eo46TcpRequestContentUseService,
    eo46TcpResponseContentAccept, eo46TcpResponseContentClose, eo46TcpResponseContentLua,
    eo46TcpResponseContentReject, eo46UseServer);
  TEnumOpenapipf47 = (
    eo47None, eo47Active, eo47Backup, eo47Disabled, eo47Inactive);
  TEnumOpenapipf48 = (
    eo48None, eo48Luascript, eo48Writetodisk);
  TEnumOpenapipf49 = (
    eo49None, eo49Forceclose, eo49HttpKeepAlive, eo49HttpServerClose, eo49HttpTunnel,
    eo49Httpclose);
  TEnumOpenapipf50 = (
    eo50None, eo50Http, eo50Https, eo50Tcp);
  TEnumOpenapipf51 = (
    eo51None, eo51Custom, eo51HttpAfterResponseAddHeader, eo51HttpAfterResponseDelHeader,
    eo51HttpAfterResponseReplaceHeader, eo51HttpAfterResponseReplaceValue,
    eo51HttpAfterResponseSetHeader, eo51HttpAfterResponseSetStatus, eo51HttpRequestAddHeader,
    eo51HttpRequestAllow, eo51HttpRequestAuth, eo51HttpRequestDelHeader,
    eo51HttpRequestDeny, eo51HttpRequestLua, eo51HttpRequestRedirect, eo51HttpRequestReplaceHeader,
    eo51HttpRequestReplacePath, eo51HttpRequestReplaceValue, eo51HttpRequestSetHeader,
    eo51HttpRequestSetMethod, eo51HttpRequestSetPath, eo51HttpRequestSetQuery,
    eo51HttpRequestSetUri, eo51HttpRequestTarpit, eo51HttpRequestUseService,
    eo51HttpResponseAddHeader, eo51HttpResponseAllow, eo51HttpResponseDelHeader,
    eo51HttpResponseDeny, eo51HttpResponseLua, eo51HttpResponseReplaceHeader,
    eo51HttpResponseReplaceValue, eo51HttpResponseSetHeader, eo51HttpResponseSetStatus,
    eo51TcpRequestConnectionAccept, eo51TcpRequestConnectionReject, eo51TcpRequestContentAccept,
    eo51TcpRequestContentLua, eo51TcpRequestContentReject, eo51TcpRequestContentUseService,
    eo51TcpResponseContentAccept, eo51TcpResponseContentClose, eo51TcpResponseContentLua,
    eo51TcpResponseContentReject, eo51UseBackend);
  TEnumOpenapipf52 = (
    eo52None, eo52AnyIpv4, eo52AnyIpv6, eo52Custom, eo52LocalhostIpv4, eo52LocalhostIpv6);
  TEnumOpenapipf53 = (
    eo53None, eo531, eo53Alert, eo53Crit, eo53Debug, eo53Emerg, eo53Err, eo53Info,
    eo53Notice, eo53Warning);
  TEnumOpenapipf54 = (
    eo54None, eo54Audit, eo54Auth, eo54Auth2, eo54Cron, eo54Cron2, eo54Daemon,
    eo54Ftp, eo54Kern, eo54Local0, eo54Local1, eo54Local2, eo54Local3,
    eo54Local4, eo54Local5, eo54Local6, eo54Local7, eo54Lpr, eo54Mail,
    eo54News, eo54Ntp, eo54Syslog, eo54User, eo54Uucp);
  TEnumOpenapipf55 = (
    eo55None, eo55Alert, eo55Crit, eo55Debug, eo55Emerg, eo55Err, eo55Info,
    eo55Notice, eo55Warning);
  TEnumOpenapipf56 = (
    eo56None, eo56Auto, eo56Intermediate, eo56Modern, eo56Old);
  TEnumOpenapipf57 = (
    eo57None, eo57Cert, eo57PreSharedKey);
  TEnumOpenapipf58 = (
    eo58None, eo581, eo58None2, eo58Start, eo58Trap);
  TEnumOpenapipf59 = (
    eo59None, eo59Auto, eo59Ikev1, eo59Ikev2);
  TEnumOpenapipf60 = (
    eo60None, eo60Aggressive, eo60Main);
  TEnumOpenapipf61 = (
    eo61None, eo61Address, eo61Asn1dn, eo61Auto, eo61DynDns, eo61Fqdn, eo61KeyidTag,
    eo61Myaddress, eo61UserFqdn);
  TEnumOpenapipf62 = (
    eo62None, eo62Force, eo62On);
  TEnumOpenapipf63 = (
    eo63None, eo63Address, eo63Any, eo63Asn1dn, eo63Auto, eo63DynDns, eo63Fqdn,
    eo63KeyidTag, eo63Peeraddress, eo63UserFqdn);
  TEnumOpenapipf64 = (
    eo64None, eo64Both, eo64Inet, eo64Inet6);
  TEnumOpenapipf65 = (
    eo65None, eo65Aes, eo65Aes128gcm, eo65Aes192gcm, eo65Aes256gcm, eo65Chacha20poly1305);
  TEnumOpenapipf66 = (
    eo66None, eo66Aesxcbc, eo66Sha1, eo66Sha256, eo66Sha384, eo66Sha512);
  TEnumOpenapipf67 = (
    eo67None, eo67Aesxcbc, eo67HmacSha1, eo67HmacSha256, eo67HmacSha384, eo67HmacSha512);
  TEnumOpenapipf67Set = set of TEnumOpenapipf67;
  TEnumOpenapipf68 = (
    eo68None, eo68Transport, eo68Tunnel, eo68Tunnel6, eo68Vti);
  TEnumOpenapipf69 = (
    eo69None, eo69Ah, eo69Esp);
  TEnumOpenapipf70 = (
    eo70None, eo70Fast, eo70Slow);
  TEnumOpenapipf71 = (
    eo71None, eo71L2, eo71L2L3, eo71L2L3L4, eo71L2L4, eo71L3, eo71L3L4, eo71L4);
  TEnumOpenapipf72 = (
    eo72None, eo72Failover, eo72Lacp, eo72Loadbalance, eo72None4, eo72Roundrobin);
  TEnumOpenapipf73 = (
    eo73None, eo73Rfc3164, eo73Rfc5424);
  TEnumOpenapipf74 = (
    eo74None, eo74Ipv4, eo74Ipv6);
  TEnumOpenapipf75 = (
    eo75None, eo75Bzip2, eo75Gzip, eo75None3, eo75Xz, eo75Zstd);
  TEnumOpenapipf76 = (
    eo76None, eo76Auto, eo76Inet, eo76Inet6);
  TEnumOpenapipf77 = (
    eo77None, eo771, eo7710, eo7711, eo7712, eo7713, eo7714, eo7715, eo7716,
    eo7717, eo773, eo774, eo775, eo776, eo777, eo778, eo779, eo77Omit);
  TEnumOpenapipf78 = (
    eo78None, eo78Md5, eo78Sha1, eo78Sha256);
  TEnumOpenapipf79 = (
    eo79None, eo79Peer, eo79Pool, eo79Server);
  TEnumOpenapipf80 = (
    eo80None, eo80SavedCfg);
  TEnumOpenapipf81 = (
    eo81None, eo81Dhcp, eo81None2, eo81Static);
  TEnumOpenapipf82 = (
    eo82None, eo826rd, eo826to4, eo82Dhcp6, eo82None4, eo82Slaac, eo82Staticv6,
    eo82Track6);
  TEnumOpenapipf83 = (
    eo83None, eo83Inet, eo83Inet6);
  TEnumOpenapipf84 = (
    eo84None, eo84Asym, eo84No, eo84Yes);
  TEnumOpenapipf85 = (
    eo85None, eo85Both, eo85V4only, eo85V6only);
  TEnumOpenapipf86 = (
    eo86None, eo86Tap, eo86Tun);
  TEnumOpenapipf87 = (
    eo87None, eo871, eo872, eo873, eo874, eo875, eo87None6);
  TEnumOpenapipf88 = (
    eo88None, eo88P2pTls);
  TEnumOpenapipf89 = (
    eo89None, eo89PingExit, eo89PingRestart);
  TEnumOpenapipf90 = (
    eo90None, eo90Keepalive, eo90Ping);
  TEnumOpenapipf91 = (
    eo91None, eo91TCP, eo91TCP4, eo91TCP6, eo91UDP, eo91UDP4, eo91UDP6);
  TEnumOpenapipf92 = (
    eo92None, eo92Basic, eo92None2, eo92Ntlm);
  TEnumOpenapipf93 = (
    eo93None, eo93Auth, eo93Crypt);
  TEnumOpenapipf94 = (
    eo94None, eo940, eo941, eo942, eo94Default);
  TEnumOpenapipf95 = (
    eo95None, eo95Net30, eo95Subnet);
  TEnumOpenapipf96 = (
    eo96None, eo96P2pTls, eo96ServerTls, eo96ServerTlsUser, eo96ServerUser);
  TEnumOpenapipf97 = (
    eo97None, eo97Bitmask, eo97Random, eo97RandomStickyAddress, eo97RoundRobin,
    eo97RoundRobinStickyAddress, eo97SourceHash);
  TEnumOpenapipf98 = (
    eo98None, eo98Ah, eo98Esp, eo98Gre, eo98Icmp, eo98Igmp, eo98Ipv6, eo98Ospf,
    eo98Pim, eo98Tcp, eo98TcpUdp, eo98Udp);
  TEnumOpenapipf99 = (
    eo99None, eo99Advanced, eo99Automatic, eo99Disabled, eo99Hybrid);
  TEnumOpenapipf100 = (
    eo100None, eo100Disable, eo100Enable, eo100Purenat);
  TEnumOpenapipf101 = (
    eo101None, eo100Allow, eo100Deny);
  TEnumOpenapipf102 = (
    eo102None, eo100Sha256, eo100Sha384, eo100Sha512);
  TEnumOpenapipf103 = (
    eo103None, eo100Descr, eo100Id, eo100If);
  TEnumOpenapipf104 = (
    eo104None, eo1001, eo100Down, eo100None3);
  TEnumOpenapipf105 = (
    eo105None, eo105Down, eo100Downlatency, eo100Downloss, eo100Downlosslatency);
  TEnumOpenapipf106 = (
    eo106None, eo100Both, eo100Enabled);
  TEnumOpenapipf107 = (
    eo107None, eo100Restart, eo100Start, eo100Stop);
  TEnumOpenapipf108 = (
    eo108None, eo100Local, eo100Remote);
  TEnumOpenapipf109 = (
    eo109None, eo1009, eo100Gb, eo100Kb, eo100Mb, eo100B);
  TEnumOpenapipf110 = (
    eo110None, eo100CBQ, eo100CODELQ, eo100FAIRQ, eo100HFSC, eo100PRIQ);
  TEnumOpenapipf111 = (
    eo111None, eo100Codel, eo100Droptail, eo100Gred, eo100Pie, eo100Red);
  TEnumOpenapipf112 = (
    eo112None, eo100Dstaddress, eo100None2, eo100Srcaddress);
  TEnumOpenapipf113 = (
    eo113None, eo100Fifo, eo100FqCodel, eo100FqPie, eo100Prio, eo100Qfq, eo100Rr,
    eo100Wf2q);
  TEnumOpenapipf114 = (
    eo114None, eo114Kb, eo114Mb, eo114B);
  TEnumOpenapipf115 = (
    eo115None, eo100Mcast, eo100Ucast);
  TEnumOpenapipf116 = (
    eo116None, eo100Carp, eo100Ipalias, eo100Other, eo100Proxyarp);
  TEnumOpenapipf117 = (
    eo117None, eo100Network, eo100Single);
  TEnumOpenapipf118 = (
    eo118None, eo100All, eo118None2, eo100Unassigned);
  TEnumOpenapipf119 = (
    eo119None, eo100SORTASC, eo100SORTDESC);
  TEnumOpenapipf120 = (
    eo120None, eo100SORTFLAGCASE, eo100SORTLOCALESTRING, eo100SORTNATURAL,
    eo100SORTNUMERIC, eo100SORTREGULAR, eo100SORTSTRING);


{ ************ Data Transfert Objects }

  TACMEAccountKey = packed record
    Accountkey: RawUtf8;
    Acmeserver: RawUtf8;
    Descr: RawUtf8;
    Email: RawUtf8;
    Name: RawUtf8;
  end;
  PACMEAccountKey = ^TACMEAccountKey;

  TACMEAccountKeyRegister = packed record
    Name: RawUtf8;
    Status: RawUtf8;
  end;
  PACMEAccountKeyRegister = ^TACMEAccountKeyRegister;

  TACMECertificate = packed record
    AActionlist: variant;
    ADomainlist: variant;
    Acmeaccount: RawUtf8;
    Descr: RawUtf8;
    Dnssleep: integer;
    Keylength: TEnumOpenapipf1;
    Keypaste: RawUtf8;
    Name: RawUtf8;
    Oscpstaple: boolean;
    Preferredchain: RawUtf8;
    Renewafter: integer;
    Status: TEnumOpenapipf2;
  end;
  PACMECertificate = ^TACMECertificate;

  TACMECertificateAction = packed record
    Command: RawUtf8;
    Method: TEnumOpenapipf3;
    Status: TEnumOpenapipf2;
  end;
  PACMECertificateAction = ^TACMECertificateAction;

  TACMECertificateDomain = packed record
    ULTRAPWD: RawUtf8;
    AcmednsPassword: RawUtf8;
    AcmednsSubdomain: RawUtf8;
    AcmednsUpdateUrl: RawUtf8;
    AcmednsUsername: RawUtf8;
    AcmeproxyEndpoint: RawUtf8;
    AcmeproxyPassword: RawUtf8;
    AcmeproxyUsername: RawUtf8;
    Active24Token: RawUtf8;
    AdApiKey: RawUtf8;
    AfApiPassword: RawUtf8;
    AfApiUsername: RawUtf8;
    AkamaiAccessToken: RawUtf8;
    AkamaiClientSecret: RawUtf8;
    AkamaiClientToken: RawUtf8;
    AkamaiHost: RawUtf8;
    AliKey: RawUtf8;
    AliSecret: RawUtf8;
    AnxToken: RawUtf8;
    Anydnschallengealias: RawUtf8;
    Anydnschallengedomain: boolean;
    ArvanToken: RawUtf8;
    AuroraKey: RawUtf8;
    AuroraSecret: RawUtf8;
    AutodnsContext: RawUtf8;
    AutodnsPassword: RawUtf8;
    AutodnsUser: RawUtf8;
    AwsAccessKeyId: RawUtf8;
    AwsDnsSlowrate: RawUtf8;
    AwsSecretAccessKey: RawUtf8;
    AzionEmail: RawUtf8;
    AzionPassword: RawUtf8;
    AzurednsAppid: RawUtf8;
    AzurednsClientsecret: RawUtf8;
    AzurednsSubscriptionid: RawUtf8;
    AzurednsTenantid: RawUtf8;
    BookmynamePassword: RawUtf8;
    BookmynameUsername: RawUtf8;
    BunnyApiKey: RawUtf8;
    CfAccountId: RawUtf8;
    CfEmail: RawUtf8;
    CfKey: RawUtf8;
    CfToken: RawUtf8;
    CfZoneId: RawUtf8;
    ClouddnsClientId: RawUtf8;
    ClouddnsEmail: RawUtf8;
    ClouddnsPassword: RawUtf8;
    CloudnsAuthId: RawUtf8;
    CloudnsAuthPassword: RawUtf8;
    CloudnsSubAuthId: RawUtf8;
    CnPassword: RawUtf8;
    CnUser: RawUtf8;
    ConohaIdentityserviceapi: RawUtf8;
    ConohaPassword: RawUtf8;
    ConohaTenantid: RawUtf8;
    ConohaUsername: RawUtf8;
    ConstellixKey: RawUtf8;
    ConstellixSecret: RawUtf8;
    CpanelApitoken: RawUtf8;
    CpanelHostname: RawUtf8;
    CpanelUsername: RawUtf8;
    CuranetAuthclientid: RawUtf8;
    CuranetAuthsecret: RawUtf8;
    CyPassword: RawUtf8;
    CyUsername: RawUtf8;
    DaApi: RawUtf8;
    DaApiInsecure: RawUtf8;
    DdApiKey: RawUtf8;
    DdApiUser: RawUtf8;
    DdnssToken: RawUtf8;
    DedynName: RawUtf8;
    DedynToken: RawUtf8;
    DefaultInfomaniakApiUrl: RawUtf8;
    DfPassword: RawUtf8;
    DfUser: RawUtf8;
    DhApiKey: RawUtf8;
    DnsexitApiKey: RawUtf8;
    DnsexitAuthPass: RawUtf8;
    DnsexitAuthUser: RawUtf8;
    DnshomeSubdomain: RawUtf8;
    DnshomeSubdomainpassword: RawUtf8;
    DnsimpleOauthToken: RawUtf8;
    DnsservicesPassword: RawUtf8;
    DnsservicesUsername: RawUtf8;
    DoApiKey: RawUtf8;
    DoLetoken: RawUtf8;
    DoPid: RawUtf8;
    DoPw: RawUtf8;
    DomeneshopSecret: RawUtf8;
    DomeneshopToken: RawUtf8;
    DpId: RawUtf8;
    DpKey: RawUtf8;
    DpiId: RawUtf8;
    DpiKey: RawUtf8;
    DuckdnsToken: RawUtf8;
    DynCustomer: RawUtf8;
    DynPassword: RawUtf8;
    DynUsername: RawUtf8;
    DynuClientid: RawUtf8;
    DynuSecret: RawUtf8;
    EasydnsKey: RawUtf8;
    EasydnsToken: RawUtf8;
    EuservPassword: RawUtf8;
    EuservUsername: RawUtf8;
    ExoscaleApiKey: RawUtf8;
    ExoscaleSecretKey: RawUtf8;
    FornexApiKey: RawUtf8;
    FreednsPassword: RawUtf8;
    FreednsUser: RawUtf8;
    GandiLivednsKey: RawUtf8;
    GcoreKey: RawUtf8;
    GdKey: RawUtf8;
    GdSecret: RawUtf8;
    GeoscalingPassword: RawUtf8;
    GeoscalingUsername: RawUtf8;
    GoogledomainsAccessToken: RawUtf8;
    GoogledomainsZone: RawUtf8;
    HePassword: RawUtf8;
    HeUsername: RawUtf8;
    HetznerToken: RawUtf8;
    HexonetLogin: RawUtf8;
    HexonetPassword: RawUtf8;
    HostingdeApikey: RawUtf8;
    HostingdeEndpoint: RawUtf8;
    HuaweicloudDomainname: RawUtf8;
    HuaweicloudPassword: RawUtf8;
    HuaweicloudUsername: RawUtf8;
    InfobloxCreds: RawUtf8;
    InfobloxServer: RawUtf8;
    InfobloxView: RawUtf8;
    InfomaniakApiToken: RawUtf8;
    InfomaniakTtl: RawUtf8;
    InternetbsApiKey: RawUtf8;
    InternetbsApiPassword: RawUtf8;
    InwxPassword: RawUtf8;
    InwxSharedSecret: RawUtf8;
    InwxUsername: RawUtf8;
    IonosPrefix: RawUtf8;
    IonosSecret: RawUtf8;
    Ipv64Token: RawUtf8;
    IspcApi: RawUtf8;
    IspcApiInsecure: RawUtf8;
    IspcPassword: RawUtf8;
    IspcUser: RawUtf8;
    JdAccessKeyId: RawUtf8;
    JdAccessKeySecret: RawUtf8;
    JdRegion: RawUtf8;
    JokerPassword: RawUtf8;
    JokerUsername: RawUtf8;
    KappernetdnsKey: RawUtf8;
    KappernetdnsSecret: RawUtf8;
    KasAuthdata: RawUtf8;
    KasAuthtype: RawUtf8;
    KasLogin: RawUtf8;
    KinghostPassword: RawUtf8;
    KinghostUsername: RawUtf8;
    KnotKey: RawUtf8;
    KnotServer: RawUtf8;
    LaId: RawUtf8;
    LaKey: RawUtf8;
    LimacityApikey: RawUtf8;
    LinodeApiKey: RawUtf8;
    LinodeV4ApiKey: RawUtf8;
    LoopiaPassword: RawUtf8;
    LoopiaUser: RawUtf8;
    LswKey: RawUtf8;
    LuaEmail: RawUtf8;
    LuaKey: RawUtf8;
    MbAk: RawUtf8;
    MbAs: RawUtf8;
    MeKey: RawUtf8;
    MeSecret: RawUtf8;
    Method: RawUtf8;
    MiabPassword: RawUtf8;
    MiabServer: RawUtf8;
    MiabUsername: RawUtf8;
    MisakaKey: RawUtf8;
    MydnsjpMasterid: RawUtf8;
    MydnsjpPassword: RawUtf8;
    Name: RawUtf8;
    NamecheapApiKey: RawUtf8;
    NamecheapUsername: RawUtf8;
    NamecomToken: RawUtf8;
    NamecomUsername: RawUtf8;
    NamesiloKey: RawUtf8;
    NaneloToken: RawUtf8;
    NcApikey: RawUtf8;
    NcApipw: RawUtf8;
    NcCid: RawUtf8;
    NederhostKey: RawUtf8;
    NeodigitApiToken: RawUtf8;
    NetlifyAccessToken: RawUtf8;
    NicClientid: RawUtf8;
    NicClientsecret: RawUtf8;
    NicPassword: RawUtf8;
    NicUsername: RawUtf8;
    NmSha256: RawUtf8;
    NmUser: RawUtf8;
    Ns1Key: RawUtf8;
    NsupdateKey: RawUtf8;
    NsupdateKeyalgo: TEnumOpenapipf4;
    NsupdateKeyname: RawUtf8;
    NsupdateServer: RawUtf8;
    NsupdateZone: RawUtf8;
    NwApiEndpoint: TEnumOpenapipf5;
    NwApiToken: RawUtf8;
    OciCliKey: RawUtf8;
    OciCliRegion: RawUtf8;
    OciCliTenancy: RawUtf8;
    OciCliUser: RawUtf8;
    One984hostingPassword: RawUtf8;
    One984hostingUsername: RawUtf8;
    OnecomPassword: RawUtf8;
    OnecomUser: RawUtf8;
    OnlineApiKey: RawUtf8;
    OpenproviderPasswordhash: RawUtf8;
    OpenproviderUser: RawUtf8;
    OvhAk: RawUtf8;
    OvhAs: RawUtf8;
    OvhCk: RawUtf8;
    OvhEndPoint: TEnumOpenapipf6;
    PddToken: RawUtf8;
    PdnsServerid: RawUtf8;
    PdnsToken: RawUtf8;
    PdnsTtl: RawUtf8;
    PdnsUrl: RawUtf8;
    PleskxmlPass: RawUtf8;
    PleskxmlUri: RawUtf8;
    PleskxmlUser: RawUtf8;
    PointhqEmail: RawUtf8;
    PointhqKey: RawUtf8;
    PorkbunApiKey: RawUtf8;
    PorkbunSecretApiKey: RawUtf8;
    RackcorpApisecret: RawUtf8;
    RackcorpApiuuid: RawUtf8;
    RackspaceApikey: RawUtf8;
    RackspaceUsername: RawUtf8;
    Rage4Token: RawUtf8;
    Rage4Username: RawUtf8;
    Rcode0ApiToken: RawUtf8;
    Rcode0Ttl: RawUtf8;
    Rcode0Url: RawUtf8;
    RegruApiPassword: RawUtf8;
    RegruApiUsername: RawUtf8;
    ScalewayApiToken: RawUtf8;
    SchlundtechPassword: RawUtf8;
    SchlundtechUser: RawUtf8;
    SelfhostdnsMap: RawUtf8;
    SelfhostdnsPassword: RawUtf8;
    SelfhostdnsUsername: RawUtf8;
    ServercowApiPassword: RawUtf8;
    ServercowApiUsername: RawUtf8;
    SimplyAccountname: RawUtf8;
    SimplyApi: RawUtf8;
    SimplyApikey: RawUtf8;
    SlKey: RawUtf8;
    Standaloneipv6: boolean;
    Standaloneport: RawUtf8;
    Standalonetlsport: RawUtf8;
    Status: TEnumOpenapipf7;
    Tele3Key: RawUtf8;
    Tele3Secret: RawUtf8;
    TencentSecretid: RawUtf8;
    TencentSecretkey: RawUtf8;
    UdrPass: RawUtf8;
    UdrUser: RawUtf8;
    UltraUsr: RawUtf8;
    UnoKey: RawUtf8;
    UnoUser: RawUtf8;
    VariomediaApiToken: RawUtf8;
    VeespPassword: RawUtf8;
    VeespUser: RawUtf8;
    VercelToken: RawUtf8;
    VscaleApiKey: RawUtf8;
    VultrApiKey: RawUtf8;
    Webrootfolder: RawUtf8;
    Webrootftpfolder: RawUtf8;
    Webrootftpftpserver: RawUtf8;
    Webrootftppassword: RawUtf8;
    Webrootftpusername: RawUtf8;
    WestKey: RawUtf8;
    WestUsername: RawUtf8;
    World4youPassword: RawUtf8;
    World4youUsername: RawUtf8;
    WsApikey: RawUtf8;
    WsApisecret: RawUtf8;
    YcFolderId: RawUtf8;
    YcSaId: RawUtf8;
    YcSaKeyFilePemB64: RawUtf8;
    YcSaKeyId: RawUtf8;
    YcZoneId: RawUtf8;
    ZiloreKey: RawUtf8;
    ZmKey: RawUtf8;
    ZoneKey: RawUtf8;
    ZoneUsername: RawUtf8;
  end;
  PACMECertificateDomain = ^TACMECertificateDomain;

  TACMECertificateIssue = packed record
    Certificate: RawUtf8;
    LastUpdated: integer;
    ResultLog: RawUtf8;
    Status: RawUtf8;
  end;
  PACMECertificateIssue = ^TACMECertificateIssue;

  TACMECertificateRenew = packed record
    Certificate: RawUtf8;
    LastUpdated: integer;
    ResultLog: RawUtf8;
    Status: RawUtf8;
  end;
  PACMECertificateRenew = ^TACMECertificateRenew;

  TACMESettings = packed record
    Enable: boolean;
    Writecerts: boolean;
  end;
  PACMESettings = ^TACMESettings;

  TARPTable = packed record
    Dnsresolve: RawUtf8;
    Expires: RawUtf8;
    Hostname: RawUtf8;
    _Interface: RawUtf8;
    IpAddress: RawUtf8;
    MacAddress: RawUtf8;
    Permanent: boolean;
    _Type: RawUtf8;
  end;
  PARPTable = ^TARPTable;

  TAuthServer = packed record
    Host: RawUtf8;
    LdapAllowUnauthenticated: boolean;
    LdapAttrGroup: RawUtf8;
    LdapAttrGroupobj: RawUtf8;
    LdapAttrMember: RawUtf8;
    LdapAttrUser: RawUtf8;
    LdapAuthcn: RawUtf8;
    LdapBasedn: RawUtf8;
    LdapBinddn: RawUtf8;
    LdapBindpw: RawUtf8;
    LdapCaref: RawUtf8;
    LdapExtendedEnabled: boolean;
    LdapExtendedQuery: RawUtf8;
    LdapNostripAt: boolean;
    LdapPamGroupdn: RawUtf8;
    LdapPort: RawUtf8;
    LdapProtver: integer;
    LdapRfc2307: boolean;
    LdapRfc2307Userdn: boolean;
    LdapScope: TEnumOpenapipf8;
    LdapTimeout: integer;
    LdapUrltype: TEnumOpenapipf9;
    LdapUtf8: boolean;
    Name: RawUtf8;
    RadiusAcctPort: RawUtf8;
    RadiusAuthPort: RawUtf8;
    RadiusNasipAttribute: RawUtf8;
    RadiusProtocol: TEnumOpenapipf10;
    RadiusSecret: RawUtf8;
    RadiusTimeout: integer;
    Refid: RawUtf8;
    _Type: TEnumOpenapipf11;
  end;
  PAuthServer = ^TAuthServer;

  TAuthenticationError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PAuthenticationError = ^TAuthenticationError;

  TAvailableInterface = packed record
    Dmesg: RawUtf8;
    _If: RawUtf8;
    InUseBy: RawUtf8;
    Mac: RawUtf8;
  end;
  PAvailableInterface = ^TAvailableInterface;

  TAvailablePackage = packed record
    Deps: TRawUtf8DynArray;
    Descr: RawUtf8;
    Installed: boolean;
    Name: RawUtf8;
    Shortname: RawUtf8;
    Version: RawUtf8;
  end;
  PAvailablePackage = ^TAvailablePackage;

  TBINDAccessList = packed record
    Description: RawUtf8;
    Entries: variant;
    Name: RawUtf8;
  end;
  PBINDAccessList = ^TBINDAccessList;

  TBINDAccessListEntry = packed record
    Description: RawUtf8;
    Value: RawUtf8;
  end;
  PBINDAccessListEntry = ^TBINDAccessListEntry;

  TBINDSettings = packed record
    BindCustomOptions: RawUtf8;
    BindDnssecValidation: TEnumOpenapipf12;
    BindForwarder: boolean;
    BindForwarderIps: TRawUtf8DynArray;
    BindGlobalSettings: RawUtf8;
    BindHideVersion: boolean;
    BindIpVersion: TEnumOpenapipf13;
    BindLogging: boolean;
    BindNotify: boolean;
    BindRamLimit: RawUtf8;
    Controlport: RawUtf8;
    EnableBind: boolean;
    Listenon: TRawUtf8DynArray;
    Listenport: RawUtf8;
    LogOnly: boolean;
    LogOptions: TEnumOpenapipf14Set;
    LogSeverity: TEnumOpenapipf15;
    RateEnabled: boolean;
    RateLimit: integer;
  end;
  PBINDSettings = ^TBINDSettings;

  TBINDSyncRemoteHost = packed record
    Ipaddress: RawUtf8;
    Password: RawUtf8;
    Syncdestinenable: boolean;
    Syncport: RawUtf8;
    Syncprotocol: TEnumOpenapipf16;
    Username: RawUtf8;
  end;
  PBINDSyncRemoteHost = ^TBINDSyncRemoteHost;

  TBINDSyncSettings = packed record
    Masterip: RawUtf8;
    Synconchanges: TEnumOpenapipf17;
    Synctimeout: integer;
  end;
  PBINDSyncSettings = ^TBINDSyncSettings;

  TBINDView = packed record
    AllowRecursion: TRawUtf8DynArray;
    BindCustomOptions: RawUtf8;
    Descr: RawUtf8;
    MatchClients: TRawUtf8DynArray;
    Name: RawUtf8;
    Recursion: boolean;
  end;
  PBINDView = ^TBINDView;

  TBINDZone = packed record
    Allowquery: TRawUtf8DynArray;
    Allowtransfer: TRawUtf8DynArray;
    Allowupdate: TRawUtf8DynArray;
    Backupkeys: boolean;
    Baseip: RawUtf8;
    Custom: RawUtf8;
    Customzonerecords: RawUtf8;
    Description: RawUtf8;
    Disabled: boolean;
    Dnssec: boolean;
    EnableUpdatepolicy: boolean;
    Expire: integer;
    Forwarders: TRawUtf8DynArray;
    Mail: RawUtf8;
    Minimum: integer;
    Name: RawUtf8;
    Nameserver: RawUtf8;
    Records: variant;
    Refresh: integer;
    Regdhcpstatic: boolean;
    Retry: integer;
    Reversev4: boolean;
    Reversev6: boolean;
    Rpz: boolean;
    Serial: integer;
    Slaveip: RawUtf8;
    Ttl: integer;
    _Type: TEnumOpenapipf18;
    Updatepolicy: RawUtf8;
    View: TRawUtf8DynArray;
  end;
  PBINDZone = ^TBINDZone;

  TBINDZoneRecord = packed record
    Name: RawUtf8;
    Priority: integer;
    Rdata: RawUtf8;
    _Type: TEnumOpenapipf19;
  end;
  PBINDZoneRecord = ^TBINDZoneRecord;

  TCARP = packed record
    Enable: boolean;
    MaintenanceMode: boolean;
  end;
  PCARP = ^TCARP;

  TCertificate = packed record
    Caref: RawUtf8;
    Crt: RawUtf8;
    Csr: RawUtf8;
    Descr: RawUtf8;
    Prv: RawUtf8;
    Refid: RawUtf8;
    _Type: TEnumOpenapipf20;
  end;
  PCertificate = ^TCertificate;

  TCertificateAuthority = packed record
    Crt: RawUtf8;
    Descr: RawUtf8;
    Prv: RawUtf8;
    Randomserial: boolean;
    Refid: RawUtf8;
    Serial: integer;
    Trust: boolean;
  end;
  PCertificateAuthority = ^TCertificateAuthority;

  TCertificateAuthorityGenerate = packed record
    Caref: RawUtf8;
    Crt: RawUtf8;
    Descr: RawUtf8;
    DigestAlg: RawUtf8;
    DnCity: RawUtf8;
    DnCommonname: RawUtf8;
    DnCountry: RawUtf8;
    DnOrganization: RawUtf8;
    DnOrganizationalunit: RawUtf8;
    DnState: RawUtf8;
    Ecname: RawUtf8;
    IsIntermediate: boolean;
    Keylen: integer;
    Keytype: TEnumOpenapipf21;
    Lifetime: integer;
    Prv: RawUtf8;
    Randomserial: boolean;
    Refid: RawUtf8;
    Serial: integer;
    Trust: boolean;
  end;
  PCertificateAuthorityGenerate = ^TCertificateAuthorityGenerate;

  TCertificateAuthorityRenew = packed record
    Caref: RawUtf8;
    Newserial: RawUtf8;
    Oldserial: RawUtf8;
    Reusekey: boolean;
    Reuseserial: boolean;
    Strictsecurity: boolean;
  end;
  PCertificateAuthorityRenew = ^TCertificateAuthorityRenew;

  TCertificateGenerate = packed record
    Caref: RawUtf8;
    Crt: RawUtf8;
    Descr: RawUtf8;
    DigestAlg: RawUtf8;
    DnCity: RawUtf8;
    DnCommonname: RawUtf8;
    DnCountry: RawUtf8;
    DnDnsSans: TRawUtf8DynArray;
    DnEmailSans: TRawUtf8DynArray;
    DnIpSans: TRawUtf8DynArray;
    DnOrganization: RawUtf8;
    DnOrganizationalunit: RawUtf8;
    DnState: RawUtf8;
    DnUriSans: TRawUtf8DynArray;
    Ecname: RawUtf8;
    Keylen: integer;
    Keytype: TEnumOpenapipf21;
    Lifetime: integer;
    Prv: RawUtf8;
    Refid: RawUtf8;
    _Type: TEnumOpenapipf20;
  end;
  PCertificateGenerate = ^TCertificateGenerate;

  TCertificatePKCS12Export = packed record
    BinaryData: RawUtf8;
    Certref: RawUtf8;
    Encryption: TEnumOpenapipf22;
    Filename: RawUtf8;
    Passphrase: RawUtf8;
  end;
  PCertificatePKCS12Export = ^TCertificatePKCS12Export;

  TCertificateRenew = packed record
    Certref: RawUtf8;
    Newserial: RawUtf8;
    Oldserial: RawUtf8;
    Reusekey: boolean;
    Reuseserial: boolean;
    Strictsecurity: boolean;
  end;
  PCertificateRenew = ^TCertificateRenew;

  TCertificateRevocationList = packed record
    Caref: RawUtf8;
    Cert: variant;
    Descr: RawUtf8;
    Lifetime: integer;
    Method: TEnumOpenapipf23;
    Refid: RawUtf8;
    Serial: integer;
    Text: RawUtf8;
  end;
  PCertificateRevocationList = ^TCertificateRevocationList;

  TCertificateRevocationListRevokedCertificate = packed record
    Caref: RawUtf8;
    Certref: RawUtf8;
    Crt: RawUtf8;
    Descr: RawUtf8;
    Prv: RawUtf8;
    Reason: integer;
    RevokeTime: integer;
    Serial: RawUtf8;
    _Type: RawUtf8;
  end;
  PCertificateRevocationListRevokedCertificate = ^TCertificateRevocationListRevokedCertificate;

  TCertificateSigningRequest = packed record
    Csr: RawUtf8;
    Descr: RawUtf8;
    DigestAlg: RawUtf8;
    DnCity: RawUtf8;
    DnCommonname: RawUtf8;
    DnCountry: RawUtf8;
    DnDnsSans: TRawUtf8DynArray;
    DnEmailSans: TRawUtf8DynArray;
    DnIpSans: TRawUtf8DynArray;
    DnOrganization: RawUtf8;
    DnOrganizationalunit: RawUtf8;
    DnState: RawUtf8;
    DnUriSans: TRawUtf8DynArray;
    Ecname: RawUtf8;
    Keylen: integer;
    Keytype: TEnumOpenapipf21;
    Lifetime: integer;
    Prv: RawUtf8;
    Refid: RawUtf8;
    _Type: TEnumOpenapipf20;
  end;
  PCertificateSigningRequest = ^TCertificateSigningRequest;

  TCertificateSigningRequestSign = packed record
    Caref: RawUtf8;
    Crt: RawUtf8;
    Csr: RawUtf8;
    Descr: RawUtf8;
    DigestAlg: RawUtf8;
    DnDnsSans: TRawUtf8DynArray;
    DnEmailSans: TRawUtf8DynArray;
    DnIpSans: TRawUtf8DynArray;
    DnUriSans: TRawUtf8DynArray;
    Lifetime: integer;
    Prv: RawUtf8;
    Refid: RawUtf8;
    _Type: TEnumOpenapipf20;
  end;
  PCertificateSigningRequestSign = ^TCertificateSigningRequestSign;

  TCommandPrompt = packed record
    Command: RawUtf8;
    Output: RawUtf8;
    ResultCode: integer;
  end;
  PCommandPrompt = ^TCommandPrompt;

  TConfigHistoryRevision = packed record
    Description: RawUtf8;
    Filesize: integer;
    Time: integer;
    Version: RawUtf8;
  end;
  PConfigHistoryRevision = ^TConfigHistoryRevision;

  TConflictError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PConflictError = ^TConflictError;

  TCronJob = packed record
    Command: RawUtf8;
    Hour: RawUtf8;
    Mday: RawUtf8;
    Minute: RawUtf8;
    Month: RawUtf8;
    Wday: RawUtf8;
    Who: RawUtf8;
  end;
  PCronJob = ^TCronJob;

  TDHCPLog = packed record
    Text: RawUtf8;
  end;
  PDHCPLog = ^TDHCPLog;

  TDHCPServer = packed record
    Defaultleasetime: integer;
    Denyunknown: TEnumOpenapipf24;
    Dhcpleaseinlocaltime: boolean;
    Disablepingcheck: boolean;
    Dnsserver: TRawUtf8DynArray;
    Domain: RawUtf8;
    Domainsearchlist: TRawUtf8DynArray;
    Enable: boolean;
    FailoverPeerip: RawUtf8;
    Gateway: RawUtf8;
    Ignorebootp: boolean;
    Ignoreclientuids: boolean;
    _Interface: RawUtf8;
    MacAllow: TRawUtf8DynArray;
    MacDeny: TRawUtf8DynArray;
    Maxleasetime: integer;
    Nonak: boolean;
    Ntpserver: TRawUtf8DynArray;
    Numberoptions: variant;
    Pool: variant;
    RangeFrom: RawUtf8;
    RangeTo: RawUtf8;
    Staticarp: boolean;
    Staticmap: variant;
    Statsgraph: boolean;
    Winsserver: TRawUtf8DynArray;
  end;
  PDHCPServer = ^TDHCPServer;

  TDHCPServerAddressPool = packed record
    Defaultleasetime: integer;
    Denyunknown: TEnumOpenapipf24;
    Dnsserver: TRawUtf8DynArray;
    Domain: RawUtf8;
    Domainsearchlist: TRawUtf8DynArray;
    Gateway: RawUtf8;
    Ignorebootp: boolean;
    Ignoreclientuids: boolean;
    MacAllow: TRawUtf8DynArray;
    MacDeny: TRawUtf8DynArray;
    Maxleasetime: integer;
    Ntpserver: TRawUtf8DynArray;
    RangeFrom: RawUtf8;
    RangeTo: RawUtf8;
    Winsserver: TRawUtf8DynArray;
  end;
  PDHCPServerAddressPool = ^TDHCPServerAddressPool;

  TDHCPServerApply = packed record
    Applied: boolean;
  end;
  PDHCPServerApply = ^TDHCPServerApply;

  TDHCPServerBackend = packed record
    Dhcpbackend: TEnumOpenapipf25;
  end;
  PDHCPServerBackend = ^TDHCPServerBackend;

  TDHCPServerCustomOption = packed record
    Number: integer;
    _Type: TEnumOpenapipf26;
    Value: RawUtf8;
  end;
  PDHCPServerCustomOption = ^TDHCPServerCustomOption;

  TDHCPServerLease = packed record
    ActiveStatus: RawUtf8;
    Descr: RawUtf8;
    Ends: RawUtf8;
    Hostname: RawUtf8;
    _If: RawUtf8;
    Ip: RawUtf8;
    Mac: RawUtf8;
    OnlineStatus: RawUtf8;
    Starts: RawUtf8;
  end;
  PDHCPServerLease = ^TDHCPServerLease;

  TDHCPServerStaticMapping = packed record
    ArpTableStaticEntry: boolean;
    Cid: RawUtf8;
    Defaultleasetime: integer;
    Descr: RawUtf8;
    Dnsserver: TRawUtf8DynArray;
    Domain: RawUtf8;
    Domainsearchlist: TRawUtf8DynArray;
    Gateway: RawUtf8;
    Hostname: RawUtf8;
    Ipaddr: RawUtf8;
    Mac: RawUtf8;
    Maxleasetime: integer;
    Ntpserver: TRawUtf8DynArray;
    Winsserver: TRawUtf8DynArray;
  end;
  PDHCPServerStaticMapping = ^TDHCPServerStaticMapping;

  TDNSForwarderApply = packed record
    Applied: boolean;
  end;
  PDNSForwarderApply = ^TDNSForwarderApply;

  TDNSForwarderHostOverride = packed record
    Aliases: variant;
    Descr: RawUtf8;
    Domain: RawUtf8;
    Host: RawUtf8;
    Ip: RawUtf8;
  end;
  PDNSForwarderHostOverride = ^TDNSForwarderHostOverride;

  TDNSForwarderHostOverrideAlias = packed record
    Description: RawUtf8;
    Domain: RawUtf8;
    Host: RawUtf8;
  end;
  PDNSForwarderHostOverrideAlias = ^TDNSForwarderHostOverrideAlias;

  TDNSResolverAccessList = packed record
    Action: TEnumOpenapipf27;
    Description: RawUtf8;
    Name: RawUtf8;
    Networks: variant;
  end;
  PDNSResolverAccessList = ^TDNSResolverAccessList;

  TDNSResolverAccessListNetwork = packed record
    Description: RawUtf8;
    Mask: integer;
    Network: RawUtf8;
  end;
  PDNSResolverAccessListNetwork = ^TDNSResolverAccessListNetwork;

  TDNSResolverApply = packed record
    Applied: boolean;
  end;
  PDNSResolverApply = ^TDNSResolverApply;

  TDNSResolverDomainOverride = packed record
    Descr: RawUtf8;
    Domain: RawUtf8;
    ForwardTlsUpstream: boolean;
    Ip: RawUtf8;
    TlsHostname: RawUtf8;
  end;
  PDNSResolverDomainOverride = ^TDNSResolverDomainOverride;

  TDNSResolverHostOverride = packed record
    Aliases: variant;
    Descr: RawUtf8;
    Domain: RawUtf8;
    Host: RawUtf8;
    Ip: TRawUtf8DynArray;
  end;
  PDNSResolverHostOverride = ^TDNSResolverHostOverride;

  TDNSResolverHostOverrideAlias = packed record
    Descr: RawUtf8;
    Domain: RawUtf8;
    Host: RawUtf8;
  end;
  PDNSResolverHostOverrideAlias = ^TDNSResolverHostOverrideAlias;

  TDNSResolverSettings = packed record
    ActiveInterface: TRawUtf8DynArray;
    CustomOptions: RawUtf8;
    Dnssec: boolean;
    Enable: boolean;
    Enablessl: boolean;
    Forwarding: boolean;
    OutgoingInterface: TRawUtf8DynArray;
    Port: RawUtf8;
    Python: boolean;
    PythonOrder: TEnumOpenapipf28;
    PythonScript: RawUtf8;
    Regdhcp: boolean;
    Regdhcpstatic: boolean;
    Regovpnclients: boolean;
    Sslcertref: RawUtf8;
    Strictout: boolean;
    SystemDomainLocalZoneType: TEnumOpenapipf29;
    Tlsport: RawUtf8;
  end;
  PDNSResolverSettings = ^TDNSResolverSettings;

  TDefaultGateway = packed record
    Defaultgw4: RawUtf8;
    Defaultgw6: RawUtf8;
  end;
  PDefaultGateway = ^TDefaultGateway;

  TEmailNotificationSettings = packed record
    AuthenticationMechanism: TEnumOpenapipf30;
    Disable: boolean;
    Fromaddress: RawUtf8;
    Ipaddress: RawUtf8;
    Notifyemailaddress: RawUtf8;
    Password: RawUtf8;
    Port: RawUtf8;
    Ssl: boolean;
    Sslvalidate: boolean;
    Timeout: integer;
    Username: RawUtf8;
  end;
  PEmailNotificationSettings = ^TEmailNotificationSettings;

  TFailedDependencyError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PFailedDependencyError = ^TFailedDependencyError;

  TFirewallAdvancedSettings = packed record
    Aliasesresolveinterval: integer;
    Checkaliasesurlcert: boolean;
  end;
  PFirewallAdvancedSettings = ^TFirewallAdvancedSettings;

  TFirewallAlias = packed record
    Address: TRawUtf8DynArray;
    Descr: RawUtf8;
    Detail: TRawUtf8DynArray;
    Name: RawUtf8;
    _Type: TEnumOpenapipf31;
  end;
  PFirewallAlias = ^TFirewallAlias;

  TFirewallApply = packed record
    Applied: boolean;
    PendingSubsystems: TRawUtf8DynArray;
  end;
  PFirewallApply = ^TFirewallApply;

  TFirewallLog = packed record
    Text: RawUtf8;
  end;
  PFirewallLog = ^TFirewallLog;

  TFirewallRule = packed record
    Ackqueue: RawUtf8;
    AssociatedRuleId: RawUtf8;
    CreatedBy: RawUtf8;
    CreatedTime: integer;
    Defaultqueue: RawUtf8;
    Descr: RawUtf8;
    Destination: RawUtf8;
    DestinationPort: RawUtf8;
    Direction: TEnumOpenapipf32;
    Disabled: boolean;
    Dnpipe: RawUtf8;
    Floating: boolean;
    Gateway: RawUtf8;
    Icmptype: TEnumOpenapipf33Set;
    _Interface: TRawUtf8DynArray;
    Ipprotocol: TEnumOpenapipf34;
    Log: boolean;
    Pdnpipe: RawUtf8;
    Protocol: TEnumOpenapipf35;
    Quick: boolean;
    Sched: RawUtf8;
    Source: RawUtf8;
    SourcePort: RawUtf8;
    Statetype: TEnumOpenapipf36;
    Tag: RawUtf8;
    TcpFlagsAny: boolean;
    TcpFlagsOutOf: TEnumOpenapipf37Set;
    TcpFlagsSet: TEnumOpenapipf37Set;
    Tracker: integer;
    _Type: TEnumOpenapipf38;
    UpdatedBy: RawUtf8;
    UpdatedTime: integer;
  end;
  PFirewallRule = ^TFirewallRule;

  TFirewallSchedule = packed record
    Active: boolean;
    Descr: RawUtf8;
    Name: RawUtf8;
    Schedlabel: RawUtf8;
    Timerange: variant;
  end;
  PFirewallSchedule = ^TFirewallSchedule;

  TFirewallScheduleTimeRange = packed record
    Day: TIntegerDynArray;
    Hour: RawUtf8;
    Month: TIntegerDynArray;
    Position: TIntegerDynArray;
    Rangedescr: RawUtf8;
  end;
  PFirewallScheduleTimeRange = ^TFirewallScheduleTimeRange;

  TFirewallState = packed record
    Age: RawUtf8;
    BytesIn: integer;
    BytesOut: integer;
    BytesTotal: integer;
    Destination: RawUtf8;
    Direction: RawUtf8;
    ExpiresIn: RawUtf8;
    _Interface: RawUtf8;
    PacketsIn: integer;
    PacketsOut: integer;
    PacketsTotal: integer;
    Protocol: RawUtf8;
    Source: RawUtf8;
    State: RawUtf8;
  end;
  PFirewallState = ^TFirewallState;

  TFirewallStatesSize = packed record
    Currentstates: integer;
    Defaultmaximumstates: integer;
    Maximumstates: integer;
  end;
  PFirewallStatesSize = ^TFirewallStatesSize;

  TForbiddenError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PForbiddenError = ^TForbiddenError;

  TGraphQL = packed record
    Query: RawUtf8;
    Variables: variant;
  end;
  PGraphQL = ^TGraphQL;

  TDtoOpenapipf2 = packed record
    ResponseId: RawUtf8;
  end;
  PDtoOpenapipf2 = ^TDtoOpenapipf2;

  TDtoOpenapipf3 = packed record
    Column: integer;
    Line: integer;
  end;
  PDtoOpenapipf3 = ^TDtoOpenapipf3;
  TDtoOpenapipf3DynArray = array of TDtoOpenapipf3;

  TDtoOpenapipf1 = packed record
    Extensions: TDtoOpenapipf2;
    Locations: TDtoOpenapipf3DynArray;
    Message: RawUtf8;
    Path: TRawUtf8DynArray;
  end;
  PDtoOpenapipf1 = ^TDtoOpenapipf1;
  TDtoOpenapipf1DynArray = array of TDtoOpenapipf1;

  TGraphQLResponse = packed record
    Data: variant;
    Errors: TDtoOpenapipf1DynArray;
  end;
  PGraphQLResponse = ^TGraphQLResponse;

  THAProxyApply = packed record
    Applied: boolean;
  end;
  PHAProxyApply = ^THAProxyApply;

  THAProxyBackend = packed record
    Acls: variant;
    Actions: variant;
    Advanced: RawUtf8;
    AdvancedBackend: RawUtf8;
    AgentChecks: boolean;
    AgentInter: integer;
    AgentPort: RawUtf8;
    Balance: TEnumOpenapipf39;
    BalanceUridepth: integer;
    BalanceUrilen: integer;
    BalanceUriwhole: boolean;
    CheckType: TEnumOpenapipf40;
    Checkinter: integer;
    ConnectionTimeout: integer;
    CookieAttributeSecure: boolean;
    EmailLevel: TEnumOpenapipf41;
    EmailTo: RawUtf8;
    Errorfiles: variant;
    HaproxyCookieDomains: TRawUtf8DynArray;
    HaproxyCookieDynamicCookieKey: RawUtf8;
    HaproxyCookieMaxidle: integer;
    HaproxyCookieMaxlife: integer;
    HttpcheckMethod: TEnumOpenapipf42;
    LogHealthChecks: boolean;
    MonitorDomain: RawUtf8;
    MonitorHttpversion: RawUtf8;
    MonitorUri: RawUtf8;
    MonitorUsername: RawUtf8;
    Name: RawUtf8;
    PersistCookieCachable: boolean;
    PersistCookieEnabled: boolean;
    PersistCookieHttponly: boolean;
    PersistCookieMode: TEnumOpenapipf43;
    PersistCookieName: RawUtf8;
    PersistCookiePostonly: boolean;
    PersistCookieSecure: boolean;
    PersistStickCookiename: RawUtf8;
    PersistStickExpire: RawUtf8;
    PersistStickLength: integer;
    PersistStickTablesize: RawUtf8;
    PersistStickyType: TEnumOpenapipf44;
    Retries: integer;
    ServerTimeout: integer;
    Servers: variant;
    StatsAdmin: RawUtf8;
    StatsDesc: RawUtf8;
    StatsEnabled: boolean;
    StatsNode: RawUtf8;
    StatsPassword: RawUtf8;
    StatsRealm: RawUtf8;
    StatsRefresh: integer;
    StatsScope: TRawUtf8DynArray;
    StatsUri: RawUtf8;
    StatsUsername: RawUtf8;
    StrictTransportSecurity: integer;
    TransparentClientip: boolean;
    TransparentInterface: RawUtf8;
  end;
  PHAProxyBackend = ^THAProxyBackend;

  THAProxyBackendACL = packed record
    Casesensitive: boolean;
    Expression: TEnumOpenapipf45;
    Name: RawUtf8;
    _Not: boolean;
    Value: RawUtf8;
  end;
  PHAProxyBackendACL = ^THAProxyBackendACL;

  THAProxyBackendAction = packed record
    Acl: RawUtf8;
    Action: TEnumOpenapipf46;
    Customaction: RawUtf8;
    DenyStatus: RawUtf8;
    Find: RawUtf8;
    Fmt: RawUtf8;
    LuaFunction: RawUtf8;
    Name: RawUtf8;
    Path: RawUtf8;
    Realm: RawUtf8;
    Reason: RawUtf8;
    Replace: RawUtf8;
    Rule: RawUtf8;
    Server: RawUtf8;
    Status: RawUtf8;
  end;
  PHAProxyBackendAction = ^THAProxyBackendAction;

  THAProxyBackendErrorFile = packed record
    Errorcode: integer;
    Errorfile: RawUtf8;
  end;
  PHAProxyBackendErrorFile = ^THAProxyBackendErrorFile;

  THAProxyBackendServer = packed record
    Address: RawUtf8;
    Name: RawUtf8;
    Port: RawUtf8;
    Serverid: integer;
    Ssl: boolean;
    Sslserververify: boolean;
    Status: TEnumOpenapipf47;
    Weight: integer;
  end;
  PHAProxyBackendServer = ^THAProxyBackendServer;

  THAProxyDNSResolver = packed record
    Name: RawUtf8;
    Port: RawUtf8;
    Server: RawUtf8;
  end;
  PHAProxyDNSResolver = ^THAProxyDNSResolver;

  THAProxyEmailMailer = packed record
    Mailserver: RawUtf8;
    Mailserverport: RawUtf8;
    Name: RawUtf8;
  end;
  PHAProxyEmailMailer = ^THAProxyEmailMailer;

  THAProxyFile = packed record
    Content: RawUtf8;
    Name: RawUtf8;
    _Type: TEnumOpenapipf48;
  end;
  PHAProxyFile = ^THAProxyFile;

  THAProxyFrontend = packed record
    AActionitems: variant;
    AErrorfiles: variant;
    AExtaddr: variant;
    Advanced: RawUtf8;
    AdvancedBind: RawUtf8;
    BackendServerpool: RawUtf8;
    ClientTimeout: integer;
    Descr: RawUtf8;
    DontlogNormal: boolean;
    Dontlognull: boolean;
    Forwardfor: boolean;
    HaAcls: variant;
    Httpclose: TEnumOpenapipf49;
    LogDetailed: boolean;
    LogSeparateErrors: boolean;
    MaxConnections: integer;
    Name: RawUtf8;
    SocketStats: boolean;
    Status: TEnumOpenapipf2;
    _Type: TEnumOpenapipf50;
  end;
  PHAProxyFrontend = ^THAProxyFrontend;

  THAProxyFrontendACL = packed record
    Casesensitive: boolean;
    Expression: TEnumOpenapipf45;
    Name: RawUtf8;
    _Not: boolean;
    Value: RawUtf8;
  end;
  PHAProxyFrontendACL = ^THAProxyFrontendACL;

  THAProxyFrontendAction = packed record
    Acl: RawUtf8;
    Action: TEnumOpenapipf51;
    Backend: RawUtf8;
    Customaction: RawUtf8;
    DenyStatus: RawUtf8;
    Find: RawUtf8;
    Fmt: RawUtf8;
    LuaFunction: RawUtf8;
    Name: RawUtf8;
    Path: RawUtf8;
    Realm: RawUtf8;
    Reason: RawUtf8;
    Replace: RawUtf8;
    Rule: RawUtf8;
    Status: RawUtf8;
  end;
  PHAProxyFrontendAction = ^THAProxyFrontendAction;

  THAProxyFrontendAddress = packed record
    ExaddrAdvanced: RawUtf8;
    Extaddr: TEnumOpenapipf52;
    ExtaddrCustom: RawUtf8;
    ExtaddrPort: RawUtf8;
    ExtaddrSsl: boolean;
  end;
  PHAProxyFrontendAddress = ^THAProxyFrontendAddress;

  THAProxyFrontendErrorFile = packed record
    Errorcode: integer;
    Errorfile: RawUtf8;
  end;
  PHAProxyFrontendErrorFile = ^THAProxyFrontendErrorFile;

  THAProxySettings = packed record
    Advanced: RawUtf8;
    Carpdev: RawUtf8;
    DnsResolvers: variant;
    EmailFrom: RawUtf8;
    EmailLevel: TEnumOpenapipf53;
    EmailMailers: variant;
    EmailMyhostname: RawUtf8;
    EmailTo: RawUtf8;
    Enable: boolean;
    Enablesync: boolean;
    HardStopAfter: RawUtf8;
    LocalstatsRefreshtime: integer;
    LocalstatsSticktableRefreshtime: integer;
    Localstatsport: RawUtf8;
    LogSendHostname: RawUtf8;
    Logfacility: TEnumOpenapipf54;
    Loglevel: TEnumOpenapipf55;
    Maxconn: integer;
    Nbthread: integer;
    Remotesyslog: RawUtf8;
    ResolverHoldvalid: RawUtf8;
    ResolverRetries: integer;
    ResolverTimeoutretry: RawUtf8;
    Sslcompatibilitymode: TEnumOpenapipf56;
    Ssldefaultdhparam: integer;
    TerminateOnReload: boolean;
  end;
  PHAProxySettings = ^THAProxySettings;

  TIPsecApply = packed record
    Applied: boolean;
  end;
  PIPsecApply = ^TIPsecApply;

  TIPsecChildSAStatus = packed record
    BytesIn: integer;
    BytesOut: integer;
    DhGroup: RawUtf8;
    Encap: boolean;
    EncrAlg: RawUtf8;
    EncrKeysize: integer;
    InstallTime: integer;
    IntegAlg: RawUtf8;
    LifeTime: integer;
    LocalTs: TRawUtf8DynArray;
    Mode: RawUtf8;
    Name: RawUtf8;
    PacketsIn: integer;
    PacketsOut: integer;
    Protocol: RawUtf8;
    RekeyTime: integer;
    RemoteTs: TRawUtf8DynArray;
    Reqid: integer;
    SpiIn: RawUtf8;
    SpiOut: RawUtf8;
    State: RawUtf8;
    Uniqueid: integer;
    UseIn: integer;
    UseOut: integer;
  end;
  PIPsecChildSAStatus = ^TIPsecChildSAStatus;

  TIPsecPhase1 = packed record
    AuthenticationMethod: TEnumOpenapipf57;
    Caref: RawUtf8;
    Certref: RawUtf8;
    Closeaction: TEnumOpenapipf58;
    Descr: RawUtf8;
    Disabled: boolean;
    DpdDelay: integer;
    DpdMaxfail: integer;
    Encryption: variant;
    GwDuplicates: boolean;
    Ikeid: integer;
    Ikeport: RawUtf8;
    Iketype: TEnumOpenapipf59;
    _Interface: RawUtf8;
    Lifetime: integer;
    Mobike: boolean;
    Mode: TEnumOpenapipf60;
    MyidData: RawUtf8;
    MyidType: TEnumOpenapipf61;
    NatTraversal: TEnumOpenapipf62;
    Nattport: RawUtf8;
    PeeridData: RawUtf8;
    PeeridType: TEnumOpenapipf63;
    PreSharedKey: RawUtf8;
    PrfselectEnable: boolean;
    Protocol: TEnumOpenapipf64;
    RandTime: integer;
    ReauthTime: integer;
    RekeyTime: integer;
    RemoteGateway: RawUtf8;
    Splitconn: boolean;
    Startaction: TEnumOpenapipf58;
  end;
  PIPsecPhase1 = ^TIPsecPhase1;

  TIPsecPhase1Encryption = packed record
    Dhgroup: integer;
    EncryptionAlgorithmKeylen: integer;
    EncryptionAlgorithmName: TEnumOpenapipf65;
    HashAlgorithm: TEnumOpenapipf66;
    PrfAlgorithm: TEnumOpenapipf66;
  end;
  PIPsecPhase1Encryption = ^TIPsecPhase1Encryption;

  TIPsecPhase2 = packed record
    Descr: RawUtf8;
    Disabled: boolean;
    EncryptionAlgorithmOption: variant;
    HashAlgorithmOption: TEnumOpenapipf67Set;
    Ikeid: integer;
    Keepalive: boolean;
    Lifetime: integer;
    LocalidAddress: RawUtf8;
    LocalidNetbits: integer;
    LocalidType: RawUtf8;
    Mode: TEnumOpenapipf68;
    NatlocalidAddress: RawUtf8;
    NatlocalidNetbits: integer;
    NatlocalidType: RawUtf8;
    Pfsgroup: integer;
    Pinghost: RawUtf8;
    Protocol: TEnumOpenapipf69;
    RandTime: integer;
    RekeyTime: integer;
    RemoteidAddress: RawUtf8;
    RemoteidNetbits: integer;
    RemoteidType: RawUtf8;
    Reqid: integer;
    Uniqid: RawUtf8;
  end;
  PIPsecPhase2 = ^TIPsecPhase2;

  TIPsecPhase2Encryption = packed record
    Keylen: integer;
    Name: TEnumOpenapipf65;
  end;
  PIPsecPhase2Encryption = ^TIPsecPhase2Encryption;

  TIPsecSAStatus = packed record
    ChildSas: variant;
    ConId: RawUtf8;
    DhGroup: RawUtf8;
    EncrAlg: RawUtf8;
    EncrKeysize: integer;
    Established: integer;
    InitiatorSpi: RawUtf8;
    IntegAlg: RawUtf8;
    LocalHost: RawUtf8;
    LocalId: RawUtf8;
    LocalPort: RawUtf8;
    NatAny: boolean;
    NatRemote: boolean;
    PrfAlg: RawUtf8;
    RekeyTime: integer;
    RemoteHost: RawUtf8;
    RemoteId: RawUtf8;
    RemotePort: RawUtf8;
    ResponderSpi: RawUtf8;
    State: RawUtf8;
    Uniqueid: integer;
    Version: integer;
  end;
  PIPsecSAStatus = ^TIPsecSAStatus;

  TInterfaceApply = packed record
    Applied: boolean;
    PendingInterfaces: TRawUtf8DynArray;
  end;
  PInterfaceApply = ^TInterfaceApply;

  TInterfaceBridge = packed record
    Bridgeif: RawUtf8;
    Descr: RawUtf8;
    Members: TRawUtf8DynArray;
  end;
  PInterfaceBridge = ^TInterfaceBridge;

  TInterfaceGRE = packed record
    AddStaticRoute: boolean;
    Descr: RawUtf8;
    Greif: RawUtf8;
    _If: RawUtf8;
    RemoteAddr: RawUtf8;
    TunnelLocalAddr: RawUtf8;
    TunnelLocalAddr6: RawUtf8;
    TunnelRemoteAddr: RawUtf8;
    TunnelRemoteAddr6: RawUtf8;
    TunnelRemoteNet: integer;
    TunnelRemoteNet6: integer;
  end;
  PInterfaceGRE = ^TInterfaceGRE;

  TInterfaceGroup = packed record
    Descr: RawUtf8;
    Ifname: RawUtf8;
    Members: TRawUtf8DynArray;
  end;
  PInterfaceGroup = ^TInterfaceGroup;

  TInterfaceLAGG = packed record
    Descr: RawUtf8;
    Failovermaster: RawUtf8;
    Lacptimeout: TEnumOpenapipf70;
    Lagghash: TEnumOpenapipf71;
    Laggif: RawUtf8;
    Members: TRawUtf8DynArray;
    Proto: TEnumOpenapipf72;
  end;
  PInterfaceLAGG = ^TInterfaceLAGG;

  TInterfaceStats = packed record
    Collisions: integer;
    Descr: RawUtf8;
    Dhcplink: RawUtf8;
    Enable: boolean;
    Gateway: RawUtf8;
    Gatewayv6: RawUtf8;
    Hwif: RawUtf8;
    Inbytes: integer;
    Inbytespass: integer;
    Inerrs: integer;
    Inpkts: integer;
    Inpktspass: integer;
    Ipaddr: RawUtf8;
    Ipaddrv6: RawUtf8;
    Linklocal: RawUtf8;
    Macaddr: RawUtf8;
    Media: RawUtf8;
    Mtu: RawUtf8;
    Name: RawUtf8;
    Outbytes: integer;
    Outbytespass: integer;
    Outerrs: integer;
    Outpkts: integer;
    Outpktspass: integer;
    Status: RawUtf8;
    Subnet: RawUtf8;
    Subnetv6: RawUtf8;
  end;
  PInterfaceStats = ^TInterfaceStats;

  TInterfaceVLAN = packed record
    Descr: RawUtf8;
    _If: RawUtf8;
    Pcp: integer;
    Tag: integer;
    Vlanif: RawUtf8;
  end;
  PInterfaceVLAN = ^TInterfaceVLAN;

  TLogSettings = packed record
    Auth: boolean;
    Dhcp: boolean;
    Disablelocallogging: boolean;
    Dpinger: boolean;
    Enableremotelogging: boolean;
    Filter: boolean;
    Filterdescriptions: integer;
    Format: TEnumOpenapipf73;
    Hostapd: boolean;
    Ipprotocol: TEnumOpenapipf74;
    Logall: boolean;
    Logcompressiontype: TEnumOpenapipf75;
    Logconfigchanges: boolean;
    Logfilesize: integer;
    Nentries: integer;
    Nologbogons: boolean;
    Nologdefaultblock: boolean;
    Nologdefaultpass: boolean;
    Nolognginx: boolean;
    Nologprivatenets: boolean;
    Ntpd: boolean;
    Portalauth: boolean;
    Ppp: boolean;
    Rawfilter: boolean;
    Remoteserver: RawUtf8;
    Remoteserver2: RawUtf8;
    Remoteserver3: RawUtf8;
    Resolver: boolean;
    Reverseorder: boolean;
    Rotatecount: integer;
    Routing: boolean;
    Sourceip: RawUtf8;
    System: boolean;
    Vpn: boolean;
  end;
  PLogSettings = ^TLogSettings;

  TMediaTypeError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PMediaTypeError = ^TMediaTypeError;

  TMethodNotAllowedError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PMethodNotAllowedError = ^TMethodNotAllowedError;

  TNTPSettings = packed record
    Clockstats: boolean;
    Dnsresolv: TEnumOpenapipf76;
    Enable: boolean;
    _Interface: TRawUtf8DynArray;
    Leapsec: RawUtf8;
    Logpeer: boolean;
    Logsys: boolean;
    Loopstats: boolean;
    Ntpmaxpeers: integer;
    Ntpmaxpoll: TEnumOpenapipf77;
    Ntpminpoll: TEnumOpenapipf77;
    Orphan: integer;
    Peerstats: boolean;
    Serverauth: boolean;
    Serverauthalgo: TEnumOpenapipf78;
    Serverauthkey: RawUtf8;
    Statsgraph: boolean;
  end;
  PNTPSettings = ^TNTPSettings;

  TNTPTimeServer = packed record
    Noselect: boolean;
    Prefer: boolean;
    Timeserver: RawUtf8;
    _Type: TEnumOpenapipf79;
  end;
  PNTPTimeServer = ^TNTPTimeServer;

  TNetworkInterface = packed record
    AdvDhcpConfigAdvanced: boolean;
    AdvDhcpConfigFileOverride: boolean;
    AdvDhcpConfigFileOverridePath: RawUtf8;
    AdvDhcpOptionModifiers: RawUtf8;
    AdvDhcpPtBackoffCutoff: integer;
    AdvDhcpPtInitialInterval: integer;
    AdvDhcpPtReboot: integer;
    AdvDhcpPtRetry: integer;
    AdvDhcpPtSelectTimeout: integer;
    AdvDhcpPtTimeout: integer;
    AdvDhcpPtValues: TEnumOpenapipf80;
    AdvDhcpRequestOptions: RawUtf8;
    AdvDhcpRequiredOptions: RawUtf8;
    AdvDhcpSendOptions: RawUtf8;
    AliasAddress: RawUtf8;
    AliasSubnet: integer;
    Blockbogons: boolean;
    Blockpriv: boolean;
    Descr: RawUtf8;
    Dhcphostname: RawUtf8;
    Dhcprejectfrom: TRawUtf8DynArray;
    Enable: boolean;
    Gateway: RawUtf8;
    Gateway6rd: RawUtf8;
    Gatewayv6: RawUtf8;
    _If: RawUtf8;
    Ipaddr: RawUtf8;
    Ipaddrv6: RawUtf8;
    Ipv6usev4iface: boolean;
    Media: RawUtf8;
    Mediaopt: RawUtf8;
    Mss: integer;
    Mtu: integer;
    Prefix6rd: RawUtf8;
    Prefix6rdV4plen: integer;
    Slaacusev4iface: boolean;
    Spoofmac: RawUtf8;
    Subnet: integer;
    Subnetv6: integer;
    Track6Interface: RawUtf8;
    Track6PrefixIdHex: RawUtf8;
    Typev4: TEnumOpenapipf81;
    Typev6: TEnumOpenapipf82;
  end;
  PNetworkInterface = ^TNetworkInterface;

  TNotAcceptableError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PNotAcceptableError = ^TNotAcceptableError;

  TNotFoundError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PNotFoundError = ^TNotFoundError;

  TOneToOneNATMapping = packed record
    Descr: RawUtf8;
    Destination: RawUtf8;
    Disabled: boolean;
    _External: RawUtf8;
    _Interface: RawUtf8;
    Ipprotocol: TEnumOpenapipf83;
    Natreflection: TEnumOpenapipf7;
    Nobinat: boolean;
    Source: RawUtf8;
  end;
  POneToOneNATMapping = ^TOneToOneNATMapping;

  TOpenVPNClient = packed record
    AllowCompression: TEnumOpenapipf84;
    AuthPass: RawUtf8;
    AuthRetryNone: boolean;
    AuthUser: RawUtf8;
    Caref: RawUtf8;
    Certref: RawUtf8;
    CreateGw: TEnumOpenapipf85;
    CustomOptions: TRawUtf8DynArray;
    DataCiphers: TRawUtf8DynArray;
    DataCiphersFallback: RawUtf8;
    Description: RawUtf8;
    DevMode: TEnumOpenapipf86;
    Digest: RawUtf8;
    Disable: boolean;
    DnsAdd: boolean;
    ExitNotify: TEnumOpenapipf87;
    InactiveSeconds: integer;
    _Interface: RawUtf8;
    KeepaliveInterval: integer;
    KeepaliveTimeout: integer;
    LocalPort: RawUtf8;
    Mode: TEnumOpenapipf88;
    Passtos: boolean;
    PingAction: TEnumOpenapipf89;
    PingActionSeconds: integer;
    PingMethod: TEnumOpenapipf90;
    PingSeconds: integer;
    Protocol: TEnumOpenapipf91;
    ProxyAddr: RawUtf8;
    ProxyAuthtype: TEnumOpenapipf92;
    ProxyPasswd: RawUtf8;
    ProxyPort: RawUtf8;
    ProxyUser: RawUtf8;
    RemoteCertTls: boolean;
    RemoteNetwork: TRawUtf8DynArray;
    RemoteNetworkv6: TRawUtf8DynArray;
    RouteNoExec: boolean;
    RouteNoPull: boolean;
    ServerAddr: RawUtf8;
    ServerPort: RawUtf8;
    Sndrcvbuf: integer;
    Tls: RawUtf8;
    TlsType: TEnumOpenapipf93;
    TlsauthKeydir: TEnumOpenapipf94;
    Topology: TEnumOpenapipf95;
    TunnelNetwork: RawUtf8;
    TunnelNetworkv6: RawUtf8;
    UdpFastIo: boolean;
    UseShaper: integer;
    VerbosityLevel: integer;
    Vpnid: integer;
    Vpnif: RawUtf8;
  end;
  POpenVPNClient = ^TOpenVPNClient;

  TOpenVPNClientSpecificOverride = packed record
    Block: boolean;
    CommonName: RawUtf8;
    CustomOptions: TRawUtf8DynArray;
    Description: RawUtf8;
    Disable: boolean;
    DnsDomain: RawUtf8;
    DnsServer1: RawUtf8;
    DnsServer2: RawUtf8;
    DnsServer3: RawUtf8;
    DnsServer4: RawUtf8;
    Gwredir: boolean;
    LocalNetwork: TRawUtf8DynArray;
    LocalNetworkv6: TRawUtf8DynArray;
    NetbiosEnable: boolean;
    NetbiosNtype: integer;
    NetbiosScope: RawUtf8;
    NtpServer1: RawUtf8;
    NtpServer2: RawUtf8;
    PushReset: boolean;
    RemoteNetwork: TRawUtf8DynArray;
    RemoteNetworkv6: TRawUtf8DynArray;
    RemoveRoute: boolean;
    ServerList: TRawUtf8DynArray;
    TunnelNetwork: RawUtf8;
    TunnelNetworkv6: RawUtf8;
    WinsServer1: RawUtf8;
    WinsServer2: RawUtf8;
  end;
  POpenVPNClientSpecificOverride = ^TOpenVPNClientSpecificOverride;

  TOpenVPNClientStatus = packed record
    ConnectTime: RawUtf8;
    LocalHost: RawUtf8;
    LocalPort: RawUtf8;
    Mgmt: RawUtf8;
    Name: RawUtf8;
    Port: RawUtf8;
    RemoteHost: RawUtf8;
    RemotePort: RawUtf8;
    State: RawUtf8;
    StateDetail: RawUtf8;
    Status: RawUtf8;
    VirtualAddr: RawUtf8;
    VirtualAddr6: RawUtf8;
    Vpnid: integer;
  end;
  POpenVPNClientStatus = ^TOpenVPNClientStatus;

  TOpenVPNServer = packed record
    AllowCompression: TEnumOpenapipf84;
    Authmode: TRawUtf8DynArray;
    Caref: RawUtf8;
    CertDepth: integer;
    Certref: RawUtf8;
    Client2client: boolean;
    Connlimit: integer;
    CreateGw: TEnumOpenapipf85;
    CustomOptions: TRawUtf8DynArray;
    DataCiphers: TRawUtf8DynArray;
    DataCiphersFallback: RawUtf8;
    Description: RawUtf8;
    DevMode: TEnumOpenapipf86;
    DhLength: RawUtf8;
    Digest: RawUtf8;
    Disable: boolean;
    DnsDomain: RawUtf8;
    DnsServer1: RawUtf8;
    DnsServer2: RawUtf8;
    DnsServer3: RawUtf8;
    DnsServer4: RawUtf8;
    DuplicateCn: boolean;
    DynamicIp: boolean;
    EcdhCurve: RawUtf8;
    Gwredir: boolean;
    Gwredir6: boolean;
    InactiveSeconds: integer;
    _Interface: RawUtf8;
    KeepaliveInterval: integer;
    KeepaliveTimeout: integer;
    LocalNetwork: TRawUtf8DynArray;
    LocalNetworkv6: TRawUtf8DynArray;
    LocalPort: RawUtf8;
    Maxclients: integer;
    Mode: TEnumOpenapipf96;
    NetbiosEnable: boolean;
    NetbiosNtype: integer;
    NetbiosScope: RawUtf8;
    NtpServer1: RawUtf8;
    NtpServer2: RawUtf8;
    Passtos: boolean;
    PingAction: TEnumOpenapipf89;
    PingActionPush: boolean;
    PingActionSeconds: integer;
    PingMethod: TEnumOpenapipf90;
    PingPush: boolean;
    PingSeconds: integer;
    Protocol: TEnumOpenapipf91;
    PushBlockoutsidedns: boolean;
    PushRegisterDns: boolean;
    RemoteCertTls: boolean;
    RemoteNetwork: TRawUtf8DynArray;
    RemoteNetworkv6: TRawUtf8DynArray;
    ServerbridgeDhcp: boolean;
    ServerbridgeDhcpEnd: RawUtf8;
    ServerbridgeDhcpStart: RawUtf8;
    ServerbridgeInterface: RawUtf8;
    ServerbridgeRoutegateway: boolean;
    Sndrcvbuf: integer;
    Strictusercn: boolean;
    Tls: RawUtf8;
    TlsType: TEnumOpenapipf93;
    TlsauthKeydir: TEnumOpenapipf94;
    Topology: TEnumOpenapipf95;
    TunnelNetwork: RawUtf8;
    TunnelNetworkv6: RawUtf8;
    UseTls: boolean;
    UsernameAsCommonName: boolean;
    VerbosityLevel: integer;
    Vpnid: integer;
    Vpnif: RawUtf8;
    WinsServer1: RawUtf8;
    WinsServer2: RawUtf8;
  end;
  POpenVPNServer = ^TOpenVPNServer;

  TOpenVPNServerConnectionStatus = packed record
    BytesRecv: integer;
    BytesSent: integer;
    Cipher: RawUtf8;
    ClientId: integer;
    CommonName: RawUtf8;
    ConnectTime: RawUtf8;
    ConnectTimeUnix: integer;
    PeerId: integer;
    RemoteHost: RawUtf8;
    UserName: RawUtf8;
    VirtualAddr: RawUtf8;
    VirtualAddr6: RawUtf8;
  end;
  POpenVPNServerConnectionStatus = ^TOpenVPNServerConnectionStatus;

  TOpenVPNServerRouteStatus = packed record
    CommonName: RawUtf8;
    LastTime: RawUtf8;
    RemoteHost: RawUtf8;
    VirtualAddr: RawUtf8;
  end;
  POpenVPNServerRouteStatus = ^TOpenVPNServerRouteStatus;

  TOpenVPNServerStatus = packed record
    Conns: variant;
    Mgmt: RawUtf8;
    Mode: RawUtf8;
    Name: RawUtf8;
    Port: RawUtf8;
    Routes: variant;
    Vpnid: integer;
  end;
  POpenVPNServerStatus = ^TOpenVPNServerStatus;

  TOutboundNATMapping = packed record
    Descr: RawUtf8;
    Destination: RawUtf8;
    DestinationPort: RawUtf8;
    Disabled: boolean;
    _Interface: RawUtf8;
    NatPort: RawUtf8;
    Nonat: boolean;
    Nosync: boolean;
    Poolopts: TEnumOpenapipf97;
    Protocol: TEnumOpenapipf98;
    Source: RawUtf8;
    SourceHashKey: RawUtf8;
    SourcePort: RawUtf8;
    StaticNatPort: boolean;
    Target: RawUtf8;
    TargetSubnet: integer;
  end;
  POutboundNATMapping = ^TOutboundNATMapping;

  TOutboundNATMode = packed record
    Mode: TEnumOpenapipf99;
  end;
  POutboundNATMode = ^TOutboundNATMode;

  TPackage = packed record
    Descr: RawUtf8;
    InstalledVersion: RawUtf8;
    LatestVersion: RawUtf8;
    Name: RawUtf8;
    Shortname: RawUtf8;
    UpdateAvailable: boolean;
  end;
  PPackage = ^TPackage;

  TPortForward = packed record
    AssociatedRuleId: RawUtf8;
    CreatedBy: RawUtf8;
    CreatedTime: integer;
    Descr: RawUtf8;
    Destination: RawUtf8;
    DestinationPort: RawUtf8;
    Disabled: boolean;
    _Interface: RawUtf8;
    Ipprotocol: TEnumOpenapipf34;
    LocalPort: RawUtf8;
    Natreflection: TEnumOpenapipf100;
    Nordr: boolean;
    Nosync: boolean;
    Protocol: TEnumOpenapipf98;
    Source: RawUtf8;
    SourcePort: RawUtf8;
    Target: RawUtf8;
    UpdatedBy: RawUtf8;
    UpdatedTime: integer;
  end;
  PPortForward = ^TPortForward;

  TRESTAPIAccessListEntry = packed record
    Descr: RawUtf8;
    Network: RawUtf8;
    Sched: RawUtf8;
    _Type: TEnumOpenapipf101;
    Users: TRawUtf8DynArray;
    Weight: integer;
  end;
  PRESTAPIAccessListEntry = ^TRESTAPIAccessListEntry;

  TRESTAPIJWT = packed record
    Token: RawUtf8;
  end;
  PRESTAPIJWT = ^TRESTAPIJWT;

  TRESTAPIKey = packed record
    Descr: RawUtf8;
    Hash: RawUtf8;
    HashAlgo: TEnumOpenapipf102;
    Key: RawUtf8;
    LengthBytes: integer;
    Username: RawUtf8;
  end;
  PRESTAPIKey = ^TRESTAPIKey;

  TRESTAPISettings = packed record
    AllowPreReleases: boolean;
    AllowedInterfaces: TRawUtf8DynArray;
    AuthMethods: TRawUtf8DynArray;
    Enabled: boolean;
    ExposeSensitiveFields: boolean;
    HaSync: boolean;
    HaSyncHosts: TRawUtf8DynArray;
    HaSyncPassword: RawUtf8;
    HaSyncUsername: RawUtf8;
    HaSyncValidateCerts: boolean;
    Hateoas: boolean;
    JwtExp: integer;
    KeepBackup: boolean;
    LogSuccessfulAuth: boolean;
    LoginProtection: boolean;
    OverrideSensitiveFields: TRawUtf8DynArray;
    ReadOnly: boolean;
    RepresentInterfacesAs: TEnumOpenapipf103;
  end;
  PRESTAPISettings = ^TRESTAPISettings;

  TRESTAPISettingsSync = packed record
    SyncData: RawUtf8;
  end;
  PRESTAPISettingsSync = ^TRESTAPISettingsSync;

  TRESTAPIVersion = packed record
    AvailableVersions: TRawUtf8DynArray;
    CurrentVersion: RawUtf8;
    InstallVersion: RawUtf8;
    LatestVersion: RawUtf8;
    LatestVersionReleaseDate: RawUtf8;
    UpdateAvailable: boolean;
  end;
  PRESTAPIVersion = ^TRESTAPIVersion;

  TRoutingApply = packed record
    Applied: boolean;
  end;
  PRoutingApply = ^TRoutingApply;

  TRoutingGateway = packed record
    ActionDisable: boolean;
    AlertInterval: integer;
    DataPayload: integer;
    Descr: RawUtf8;
    Disabled: boolean;
    DpingerDontAddStaticRoute: boolean;
    ForceDown: boolean;
    Gateway: RawUtf8;
    GwDownKillStates: TEnumOpenapipf104;
    _Interface: RawUtf8;
    Interval: integer;
    Ipprotocol: TEnumOpenapipf83;
    Latencyhigh: integer;
    Latencylow: integer;
    LossInterval: integer;
    Losshigh: integer;
    Losslow: integer;
    Monitor: RawUtf8;
    MonitorDisable: boolean;
    Name: RawUtf8;
    Nonlocalgateway: boolean;
    TimePeriod: integer;
    Weight: integer;
  end;
  PRoutingGateway = ^TRoutingGateway;

  TRoutingGatewayGroup = packed record
    Descr: RawUtf8;
    Ipprotocol: RawUtf8;
    Name: RawUtf8;
    Priorities: variant;
    Trigger: TEnumOpenapipf105;
  end;
  PRoutingGatewayGroup = ^TRoutingGatewayGroup;

  TRoutingGatewayGroupPriority = packed record
    Gateway: RawUtf8;
    Tier: integer;
    VirtualIp: RawUtf8;
  end;
  PRoutingGatewayGroupPriority = ^TRoutingGatewayGroupPriority;

  TRoutingGatewayStatus = packed record
    Delay: single;
    Loss: single;
    Monitorip: RawUtf8;
    Name: RawUtf8;
    Srcip: RawUtf8;
    Status: RawUtf8;
    Stddev: single;
    Substatus: RawUtf8;
  end;
  PRoutingGatewayStatus = ^TRoutingGatewayStatus;

  TSSH = packed record
    Enable: boolean;
    Port: RawUtf8;
    Sshdagentforwarding: boolean;
    Sshdkeyonly: TEnumOpenapipf106;
  end;
  PSSH = ^TSSH;

  TServerError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PServerError = ^TServerError;

  TService = packed record
    Action: TEnumOpenapipf107;
    Description: RawUtf8;
    Enabled: boolean;
    Name: RawUtf8;
    Status: boolean;
  end;
  PService = ^TService;

  TServiceUnavailableError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PServiceUnavailableError = ^TServiceUnavailableError;

  TServiceWatchdog = packed record
    Description: RawUtf8;
    Enabled: boolean;
    Name: RawUtf8;
    Notify: boolean;
  end;
  PServiceWatchdog = ^TServiceWatchdog;

  TStaticRoute = packed record
    Descr: RawUtf8;
    Disabled: boolean;
    Gateway: RawUtf8;
    Network: RawUtf8;
  end;
  PStaticRoute = ^TStaticRoute;

  TSuccess = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PSuccess = ^TSuccess;

  TSystemConsole = packed record
    PasswdProtectConsole: boolean;
  end;
  PSystemConsole = ^TSystemConsole;

  TSystemDNS = packed record
    Dnsallowoverride: boolean;
    Dnslocalhost: TEnumOpenapipf108;
    Dnsserver: TRawUtf8DynArray;
  end;
  PSystemDNS = ^TSystemDNS;

  TSystemHalt = packed record
    DryRun: boolean;
  end;
  PSystemHalt = ^TSystemHalt;

  TSystemHostname = packed record
    Domain: RawUtf8;
    Hostname: RawUtf8;
  end;
  PSystemHostname = ^TSystemHostname;

  TSystemLog = packed record
    Text: RawUtf8;
  end;
  PSystemLog = ^TSystemLog;

  TSystemReboot = packed record
    DryRun: boolean;
  end;
  PSystemReboot = ^TSystemReboot;

  TSystemStatus = packed record
    BiosDate: RawUtf8;
    BiosVendor: RawUtf8;
    BiosVersion: RawUtf8;
    CpuCount: integer;
    CpuLoadAvg: TSingleDynArray;
    CpuModel: RawUtf8;
    CpuUsage: single;
    DiskUsage: single;
    KernelPti: boolean;
    MbufUsage: single;
    MdsMitigation: RawUtf8;
    MemUsage: single;
    NetgateId: RawUtf8;
    Platform: RawUtf8;
    Serial: RawUtf8;
    SwapUsage: single;
    TempC: single;
    TempF: single;
    Uptime: RawUtf8;
  end;
  PSystemStatus = ^TSystemStatus;

  TSystemTunable = packed record
    Descr: RawUtf8;
    Tunable: RawUtf8;
    Value: RawUtf8;
  end;
  PSystemTunable = ^TSystemTunable;

  TSystemVersion = packed record
    Base: RawUtf8;
    Buildtime: RawUtf8;
    Patch: RawUtf8;
    Version: RawUtf8;
  end;
  PSystemVersion = ^TSystemVersion;

  TTrafficShaper = packed record
    Bandwidth: integer;
    Bandwidthtype: TEnumOpenapipf109;
    Enabled: boolean;
    _Interface: RawUtf8;
    Name: RawUtf8;
    Qlimit: integer;
    Queue: variant;
    Scheduler: TEnumOpenapipf110;
    Tbrconfig: integer;
  end;
  PTrafficShaper = ^TTrafficShaper;

  TTrafficShaperLimiter = packed record
    Aqm: TEnumOpenapipf111;
    Bandwidth: variant;
    Buckets: integer;
    Delay: integer;
    Description: RawUtf8;
    Ecn: boolean;
    Enabled: boolean;
    Mask: TEnumOpenapipf112;
    Maskbits: integer;
    Maskbitsv6: integer;
    Name: RawUtf8;
    Number: integer;
    ParamCodelInterval: integer;
    ParamCodelTarget: integer;
    ParamFqCodelFlows: integer;
    ParamFqCodelInterval: integer;
    ParamFqCodelLimit: integer;
    ParamFqCodelQuantum: integer;
    ParamFqCodelTarget: integer;
    ParamFqPieAlpha: integer;
    ParamFqPieBeta: integer;
    ParamFqPieFlows: integer;
    ParamFqPieLimit: integer;
    ParamFqPieMaxBurst: integer;
    ParamFqPieMaxEcnth: integer;
    ParamFqPieQuantum: integer;
    ParamFqPieTarget: integer;
    ParamFqPieTupdate: integer;
    ParamGredMaxP: integer;
    ParamGredMaxTh: integer;
    ParamGredMinTh: integer;
    ParamGredWQ: integer;
    ParamPieAlpha: integer;
    ParamPieBeta: integer;
    ParamPieMaxBurst: integer;
    ParamPieMaxEcnth: integer;
    ParamPieTarget: integer;
    ParamPieTupdate: integer;
    ParamRedMaxP: integer;
    ParamRedMaxTh: integer;
    ParamRedMinTh: integer;
    ParamRedWQ: integer;
    PieCapdrop: boolean;
    PieOnoff: boolean;
    PiePderand: boolean;
    PieQdelay: boolean;
    Plr: single;
    Qlimit: integer;
    Queue: variant;
    Sched: TEnumOpenapipf113;
  end;
  PTrafficShaperLimiter = ^TTrafficShaperLimiter;

  TTrafficShaperLimiterBandwidth = packed record
    Bw: integer;
    Bwscale: TEnumOpenapipf114;
    Bwsched: RawUtf8;
  end;
  PTrafficShaperLimiterBandwidth = ^TTrafficShaperLimiterBandwidth;

  TTrafficShaperLimiterQueue = packed record
    Aqm: TEnumOpenapipf111;
    Buckets: integer;
    Description: RawUtf8;
    Ecn: boolean;
    Enabled: boolean;
    Mask: TEnumOpenapipf112;
    Maskbits: integer;
    Maskbitsv6: integer;
    Name: RawUtf8;
    Number: integer;
    ParamCodelInterval: integer;
    ParamCodelTarget: integer;
    ParamGredMaxP: integer;
    ParamGredMaxTh: integer;
    ParamGredMinTh: integer;
    ParamGredWQ: integer;
    ParamPieAlpha: integer;
    ParamPieBeta: integer;
    ParamPieMaxBurst: integer;
    ParamPieMaxEcnth: integer;
    ParamPieTarget: integer;
    ParamPieTupdate: integer;
    ParamRedMaxP: integer;
    ParamRedMaxTh: integer;
    ParamRedMinTh: integer;
    ParamRedWQ: integer;
    PieCapdrop: boolean;
    PieOnoff: boolean;
    PiePderand: boolean;
    PieQdelay: boolean;
    Plr: single;
    Qlimit: integer;
    Weight: integer;
  end;
  PTrafficShaperLimiterQueue = ^TTrafficShaperLimiterQueue;

  TTrafficShaperQueue = packed record
    Bandwidth: integer;
    Bandwidthtype: TEnumOpenapipf109;
    Borrow: boolean;
    Buckets: integer;
    Codel: boolean;
    Default: boolean;
    Description: RawUtf8;
    Ecn: boolean;
    Enabled: boolean;
    Hogs: integer;
    _Interface: RawUtf8;
    Linkshare: boolean;
    LinkshareD: integer;
    LinkshareM1: RawUtf8;
    LinkshareM2: RawUtf8;
    Name: RawUtf8;
    Priority: integer;
    Qlimit: integer;
    Realtime: boolean;
    RealtimeD: integer;
    RealtimeM1: RawUtf8;
    RealtimeM2: RawUtf8;
    Red: boolean;
    Rio: boolean;
    Upperlimit: boolean;
    UpperlimitD: integer;
    UpperlimitM1: RawUtf8;
    UpperlimitM2: RawUtf8;
  end;
  PTrafficShaperQueue = ^TTrafficShaperQueue;

  TUnprocessableContentError = packed record
    Links: variant;
    Code: integer;
    Data: variant;
    Message: RawUtf8;
    ResponseId: RawUtf8;
    Status: RawUtf8;
  end;
  PUnprocessableContentError = ^TUnprocessableContentError;

  TUser = packed record
    Authorizedkeys: RawUtf8;
    Cert: TRawUtf8DynArray;
    Descr: RawUtf8;
    Disabled: boolean;
    Expires: RawUtf8;
    Ipsecpsk: RawUtf8;
    Name: RawUtf8;
    Password: RawUtf8;
    Priv: TRawUtf8DynArray;
    Scope: RawUtf8;
    Uid: integer;
  end;
  PUser = ^TUser;

  TUserGroup = packed record
    Description: RawUtf8;
    Gid: integer;
    Member: TRawUtf8DynArray;
    Name: RawUtf8;
    Priv: TRawUtf8DynArray;
    Scope: TEnumOpenapipf108;
  end;
  PUserGroup = ^TUserGroup;

  TVirtualIP = packed record
    Advbase: integer;
    Advskew: integer;
    CarpMode: TEnumOpenapipf115;
    CarpPeer: RawUtf8;
    CarpStatus: RawUtf8;
    Descr: RawUtf8;
    _Interface: RawUtf8;
    Mode: TEnumOpenapipf116;
    Noexpand: boolean;
    Password: RawUtf8;
    Subnet: RawUtf8;
    SubnetBits: integer;
    _Type: TEnumOpenapipf117;
    Uniqid: RawUtf8;
    Vhid: integer;
  end;
  PVirtualIP = ^TVirtualIP;

  TVirtualIPApply = packed record
    Applied: boolean;
  end;
  PVirtualIPApply = ^TVirtualIPApply;

  TWakeOnLANSend = packed record
    _Interface: RawUtf8;
    MacAddr: RawUtf8;
  end;
  PWakeOnLANSend = ^TWakeOnLANSend;

  TWebGUISettings = packed record
    Port: RawUtf8;
    Protocol: TEnumOpenapipf16;
    Sslcertref: RawUtf8;
  end;
  PWebGUISettings = ^TWebGUISettings;

  TWireGuardApply = packed record
    Applied: boolean;
  end;
  PWireGuardApply = ^TWireGuardApply;

  TWireGuardPeer = packed record
    Allowedips: variant;
    Descr: RawUtf8;
    Enabled: boolean;
    Endpoint: RawUtf8;
    Persistentkeepalive: integer;
    Port: RawUtf8;
    Presharedkey: RawUtf8;
    Publickey: RawUtf8;
    Tun: RawUtf8;
  end;
  PWireGuardPeer = ^TWireGuardPeer;

  TWireGuardPeerAllowedIP = packed record
    Address: RawUtf8;
    Descr: RawUtf8;
    Mask: integer;
  end;
  PWireGuardPeerAllowedIP = ^TWireGuardPeerAllowedIP;

  TWireGuardSettings = packed record
    Enable: boolean;
    HidePeers: boolean;
    HideSecrets: boolean;
    InterfaceGroup: TEnumOpenapipf118;
    KeepConf: boolean;
    ResolveInterval: integer;
    ResolveIntervalTrack: boolean;
  end;
  PWireGuardSettings = ^TWireGuardSettings;

  TWireGuardTunnel = packed record
    Addresses: variant;
    Enabled: boolean;
    Listenport: RawUtf8;
    Mtu: integer;
    Name: RawUtf8;
    Privatekey: RawUtf8;
    Publickey: RawUtf8;
  end;
  PWireGuardTunnel = ^TWireGuardTunnel;

  TWireGuardTunnelAddress = packed record
    Address: RawUtf8;
    Descr: RawUtf8;
    Mask: integer;
  end;
  PWireGuardTunnelAddress = ^TWireGuardTunnelAddress;



const
  // define how enums/sets are actually transmitted as JSON array of string
  ENUMOPENAPIPF1_TXT: array[TEnumOpenapipf1] of RawUtf8 = (
    '', '2048', '3072', '4096', 'custom', 'ec-256', 'ec-384');
  ENUMOPENAPIPF2_TXT: array[TEnumOpenapipf2] of RawUtf8 = (
    '', 'active', 'disabled');
  ENUMOPENAPIPF3_TXT: array[TEnumOpenapipf3] of RawUtf8 = (
    '', 'php_command', 'servicerestart', 'shellcommand', 'xmlrpcservicerestart');
  ENUMOPENAPIPF4_TXT: array[TEnumOpenapipf4] of RawUtf8 = (
    '', '', '157', '161', '162', '163', '164', '165');
  ENUMOPENAPIPF5_TXT: array[TEnumOpenapipf5] of RawUtf8 = (
    '', '', 'https:\/\/core.thermo.io', 'https:\/\/my.futurehosting.com',
    'https:\/\/portal.nexcess.net');
  ENUMOPENAPIPF6_TXT: array[TEnumOpenapipf6] of RawUtf8 = (
    '', '', 'kimsufi-ca', 'kimsufi-eu', 'ovh-ca', 'ovh-eu', 'runabove-ca',
    'soyoustart-ca', 'soyoustart-eu');
  ENUMOPENAPIPF7_TXT: array[TEnumOpenapipf7] of RawUtf8 = (
    '', 'disable', 'enable');
  ENUMOPENAPIPF8_TXT: array[TEnumOpenapipf8] of RawUtf8 = (
    '', 'one', 'subtree');
  ENUMOPENAPIPF9_TXT: array[TEnumOpenapipf9] of RawUtf8 = (
    '', 'SSL/TLS Encrypted', 'STARTTLS Encrypt', 'Standard TCP');
  ENUMOPENAPIPF10_TXT: array[TEnumOpenapipf10] of RawUtf8 = (
    '', 'CHAP_MD5', 'MSCHAPv1', 'MSCHAPv2', 'PAP');
  ENUMOPENAPIPF11_TXT: array[TEnumOpenapipf11] of RawUtf8 = (
    '', 'ldap', 'radius');
  ENUMOPENAPIPF12_TXT: array[TEnumOpenapipf12] of RawUtf8 = (
    '', 'auto', 'off', 'on');
  ENUMOPENAPIPF13_TXT: array[TEnumOpenapipf13] of RawUtf8 = (
    '', '', '-4', '-6');
  ENUMOPENAPIPF14_TXT: array[TEnumOpenapipf14] of RawUtf8 = (
    '', 'client', 'config', 'database', 'default', 'dispatch', 'dnssec',
    'general', 'lame-servers', 'network', 'notify', 'queries', 'resolver',
    'security', 'unmatched', 'update', 'xfer-in', 'xfer-out');
  ENUMOPENAPIPF15_TXT: array[TEnumOpenapipf15] of RawUtf8 = (
    '', 'critical', 'debug 1', 'debug 3', 'debug 5', 'dynamic', 'error',
    'info', 'notice', 'warning');
  ENUMOPENAPIPF16_TXT: array[TEnumOpenapipf16] of RawUtf8 = (
    '', 'http', 'https');
  ENUMOPENAPIPF17_TXT: array[TEnumOpenapipf17] of RawUtf8 = (
    '', 'auto', 'disabled', 'manual');
  ENUMOPENAPIPF18_TXT: array[TEnumOpenapipf18] of RawUtf8 = (
    '', 'forward', 'master', 'redirect', 'slave');
  ENUMOPENAPIPF19_TXT: array[TEnumOpenapipf19] of RawUtf8 = (
    '', 'A', 'AAAA', 'CNAME', 'LOC', 'MX', 'NS', 'PTR', 'SPF', 'SRV', 'TXT');
  ENUMOPENAPIPF20_TXT: array[TEnumOpenapipf20] of RawUtf8 = (
    '', 'server', 'user');
  ENUMOPENAPIPF21_TXT: array[TEnumOpenapipf21] of RawUtf8 = (
    '', 'ECDSA', 'RSA');
  ENUMOPENAPIPF22_TXT: array[TEnumOpenapipf22] of RawUtf8 = (
    '', 'high', 'legacy', 'low');
  ENUMOPENAPIPF23_TXT: array[TEnumOpenapipf23] of RawUtf8 = (
    '', 'existing', 'internal');
  ENUMOPENAPIPF24_TXT: array[TEnumOpenapipf24] of RawUtf8 = (
    '', 'class', 'enabled');
  ENUMOPENAPIPF25_TXT: array[TEnumOpenapipf25] of RawUtf8 = (
    '', 'isc', 'kea');
  ENUMOPENAPIPF26_TXT: array[TEnumOpenapipf26] of RawUtf8 = (
    '', 'boolean', 'ip-address', 'signed integer 16', 'signed integer 32',
    'signed integer 8', 'string', 'text', 'unsigned integer 16', 'unsigned integer 32',
    'unsigned integer 8');
  ENUMOPENAPIPF27_TXT: array[TEnumOpenapipf27] of RawUtf8 = (
    '', 'allow', 'allow snoop', 'deny', 'deny nonlocal', 'refuse', 'refuse nonlocal');
  ENUMOPENAPIPF28_TXT: array[TEnumOpenapipf28] of RawUtf8 = (
    '', 'post_validator', 'pre_validator');
  ENUMOPENAPIPF29_TXT: array[TEnumOpenapipf29] of RawUtf8 = (
    '', 'deny', 'inform', 'inform_deny', 'nodefault', 'redirect', 'refuse',
    'static', 'transparent', 'typetransparent');
  ENUMOPENAPIPF30_TXT: array[TEnumOpenapipf30] of RawUtf8 = (
    '', 'LOGIN', 'PLAIN');
  ENUMOPENAPIPF31_TXT: array[TEnumOpenapipf31] of RawUtf8 = (
    '', 'host', 'network', 'port');
  ENUMOPENAPIPF32_TXT: array[TEnumOpenapipf32] of RawUtf8 = (
    '', 'any', 'in', 'out');
  ENUMOPENAPIPF33_TXT: array[TEnumOpenapipf33] of RawUtf8 = (
    '', 'althost', 'any', 'dataconv', 'echorep', 'echoreq', 'inforep',
    'inforeq', 'ipv6-here', 'ipv6-where', 'maskrep', 'maskreq', 'mobredir',
    'mobregrep', 'mobregreq', 'paramprob', 'photuris', 'redir', 'routeradv',
    'routersol', 'skip', 'squench', 'timerep', 'timereq', 'timex', 'trace',
    'unreach');
  ENUMOPENAPIPF34_TXT: array[TEnumOpenapipf34] of RawUtf8 = (
    '', 'inet', 'inet46', 'inet6');
  ENUMOPENAPIPF35_TXT: array[TEnumOpenapipf35] of RawUtf8 = (
    '', 'ah', 'carp', 'esp', 'gre', 'icmp', 'igmp', 'ipv6', 'ospf', 'pfsync',
    'pim', 'tcp', 'tcp/udp', 'udp');
  ENUMOPENAPIPF36_TXT: array[TEnumOpenapipf36] of RawUtf8 = (
    '', 'keep state', 'none', 'sloppy state', 'synproxy state');
  ENUMOPENAPIPF37_TXT: array[TEnumOpenapipf37] of RawUtf8 = (
    '', 'ack', 'cwr', 'ece', 'fin', 'psh', 'rst', 'syn', 'urg');
  ENUMOPENAPIPF38_TXT: array[TEnumOpenapipf38] of RawUtf8 = (
    '', 'block', 'pass', 'reject');
  ENUMOPENAPIPF39_TXT: array[TEnumOpenapipf39] of RawUtf8 = (
    '', '', 'leastconn', 'roundrobin', 'source', 'static-rr', 'uri');
  ENUMOPENAPIPF40_TXT: array[TEnumOpenapipf40] of RawUtf8 = (
    '', 'Basic', 'ESMTP', 'HTTP', 'LDAP', 'MySQL', 'PostgreSQL', 'Redis',
    'SMTP', 'SSL', 'none');
  ENUMOPENAPIPF41_TXT: array[TEnumOpenapipf41] of RawUtf8 = (
    '', '', 'alert', 'crit', 'debug', 'dontlog', 'emerg', 'err', 'info',
    'notice', 'warning');
  ENUMOPENAPIPF42_TXT: array[TEnumOpenapipf42] of RawUtf8 = (
    '', 'DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'TRACE');
  ENUMOPENAPIPF43_TXT: array[TEnumOpenapipf43] of RawUtf8 = (
    '', 'insert-only', 'insert-only-silent', 'passive', 'passive-session-prefix',
    'passive-silent', 'reset', 'session-prefix', 'set', 'set-silent');
  ENUMOPENAPIPF44_TXT: array[TEnumOpenapipf44] of RawUtf8 = (
    '', 'none', 'stick_cookie_value', 'stick_rdp_cookie', 'stick_sourceipv4',
    'stick_sourceipv6', 'stick_sslsessionid');
  ENUMOPENAPIPF45_TXT: array[TEnumOpenapipf45] of RawUtf8 = (
    '', 'backendservercount', 'custom', 'host_contains', 'host_ends_with',
    'host_matches', 'host_regex', 'host_starts_with', 'path_contains',
    'path_dir', 'path_ends_with', 'path_matches', 'path_regex', 'path_starts_with',
    'source_ip', 'ssl_c_ca_commonname', 'ssl_c_verify', 'ssl_c_verify_code',
    'ssl_sni_contains', 'ssl_sni_ends_with', 'ssl_sni_matches', 'ssl_sni_regex',
    'ssl_sni_starts_with', 'traffic_is_http', 'traffic_is_ssl', 'url_parameter');
  ENUMOPENAPIPF46_TXT: array[TEnumOpenapipf46] of RawUtf8 = (
    '', 'custom', 'http-after-response_add-header', 'http-after-response_del-header',
    'http-after-response_replace-header', 'http-after-response_replace-value',
    'http-after-response_set-header', 'http-after-response_set-status',
    'http-request_add-header', 'http-request_allow', 'http-request_auth',
    'http-request_del-header', 'http-request_deny', 'http-request_lua',
    'http-request_redirect', 'http-request_replace-header', 'http-request_replace-path',
    'http-request_replace-value', 'http-request_set-header', 'http-request_set-method',
    'http-request_set-path', 'http-request_set-query', 'http-request_set-uri',
    'http-request_tarpit', 'http-request_use-service', 'http-response_add-header',
    'http-response_allow', 'http-response_del-header', 'http-response_deny',
    'http-response_lua', 'http-response_replace-header', 'http-response_replace-value',
    'http-response_set-header', 'http-response_set-status', 'tcp-request_connection_accept',
    'tcp-request_connection_reject', 'tcp-request_content_accept', 'tcp-request_content_lua',
    'tcp-request_content_reject', 'tcp-request_content_use-service', 'tcp-response_content_accept',
    'tcp-response_content_close', 'tcp-response_content_lua', 'tcp-response_content_reject',
    'use_server');
  ENUMOPENAPIPF47_TXT: array[TEnumOpenapipf47] of RawUtf8 = (
    '', 'active', 'backup', 'disabled', 'inactive');
  ENUMOPENAPIPF48_TXT: array[TEnumOpenapipf48] of RawUtf8 = (
    '', 'luascript', 'writetodisk');
  ENUMOPENAPIPF49_TXT: array[TEnumOpenapipf49] of RawUtf8 = (
    '', 'forceclose', 'http-keep-alive', 'http-server-close', 'http-tunnel',
    'httpclose');
  ENUMOPENAPIPF50_TXT: array[TEnumOpenapipf50] of RawUtf8 = (
    '', 'http', 'https', 'tcp');
  ENUMOPENAPIPF51_TXT: array[TEnumOpenapipf51] of RawUtf8 = (
    '', 'custom', 'http-after-response_add-header', 'http-after-response_del-header',
    'http-after-response_replace-header', 'http-after-response_replace-value',
    'http-after-response_set-header', 'http-after-response_set-status',
    'http-request_add-header', 'http-request_allow', 'http-request_auth',
    'http-request_del-header', 'http-request_deny', 'http-request_lua',
    'http-request_redirect', 'http-request_replace-header', 'http-request_replace-path',
    'http-request_replace-value', 'http-request_set-header', 'http-request_set-method',
    'http-request_set-path', 'http-request_set-query', 'http-request_set-uri',
    'http-request_tarpit', 'http-request_use-service', 'http-response_add-header',
    'http-response_allow', 'http-response_del-header', 'http-response_deny',
    'http-response_lua', 'http-response_replace-header', 'http-response_replace-value',
    'http-response_set-header', 'http-response_set-status', 'tcp-request_connection_accept',
    'tcp-request_connection_reject', 'tcp-request_content_accept', 'tcp-request_content_lua',
    'tcp-request_content_reject', 'tcp-request_content_use-service', 'tcp-response_content_accept',
    'tcp-response_content_close', 'tcp-response_content_lua', 'tcp-response_content_reject',
    'use_backend');
  ENUMOPENAPIPF52_TXT: array[TEnumOpenapipf52] of RawUtf8 = (
    '', 'any_ipv4', 'any_ipv6', 'custom', 'localhost_ipv4', 'localhost_ipv6');
  ENUMOPENAPIPF53_TXT: array[TEnumOpenapipf53] of RawUtf8 = (
    '', '', 'alert', 'crit', 'debug', 'emerg', 'err', 'info', 'notice',
    'warning');
  ENUMOPENAPIPF54_TXT: array[TEnumOpenapipf54] of RawUtf8 = (
    '', 'audit', 'auth', 'auth2', 'cron', 'cron2', 'daemon', 'ftp', 'kern',
    'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6',
    'local7', 'lpr', 'mail', 'news', 'ntp', 'syslog', 'user', 'uucp');
  ENUMOPENAPIPF55_TXT: array[TEnumOpenapipf55] of RawUtf8 = (
    '', 'alert', 'crit', 'debug', 'emerg', 'err', 'info', 'notice', 'warning');
  ENUMOPENAPIPF56_TXT: array[TEnumOpenapipf56] of RawUtf8 = (
    '', 'auto', 'intermediate', 'modern', 'old');
  ENUMOPENAPIPF57_TXT: array[TEnumOpenapipf57] of RawUtf8 = (
    '', 'cert', 'pre_shared_key');
  ENUMOPENAPIPF58_TXT: array[TEnumOpenapipf58] of RawUtf8 = (
    '', '', 'none', 'start', 'trap');
  ENUMOPENAPIPF59_TXT: array[TEnumOpenapipf59] of RawUtf8 = (
    '', 'auto', 'ikev1', 'ikev2');
  ENUMOPENAPIPF60_TXT: array[TEnumOpenapipf60] of RawUtf8 = (
    '', 'aggressive', 'main');
  ENUMOPENAPIPF61_TXT: array[TEnumOpenapipf61] of RawUtf8 = (
    '', 'address', 'asn1dn', 'auto', 'dyn_dns', 'fqdn', 'keyid tag', 'myaddress',
    'user_fqdn');
  ENUMOPENAPIPF62_TXT: array[TEnumOpenapipf62] of RawUtf8 = (
    '', 'force', 'on');
  ENUMOPENAPIPF63_TXT: array[TEnumOpenapipf63] of RawUtf8 = (
    '', 'address', 'any', 'asn1dn', 'auto', 'dyn_dns', 'fqdn', 'keyid tag',
    'peeraddress', 'user_fqdn');
  ENUMOPENAPIPF64_TXT: array[TEnumOpenapipf64] of RawUtf8 = (
    '', 'both', 'inet', 'inet6');
  ENUMOPENAPIPF65_TXT: array[TEnumOpenapipf65] of RawUtf8 = (
    '', 'aes', 'aes128gcm', 'aes192gcm', 'aes256gcm', 'chacha20poly1305');
  ENUMOPENAPIPF66_TXT: array[TEnumOpenapipf66] of RawUtf8 = (
    '', 'aesxcbc', 'sha1', 'sha256', 'sha384', 'sha512');
  ENUMOPENAPIPF67_TXT: array[TEnumOpenapipf67] of RawUtf8 = (
    '', 'aesxcbc', 'hmac_sha1', 'hmac_sha256', 'hmac_sha384', 'hmac_sha512');
  ENUMOPENAPIPF68_TXT: array[TEnumOpenapipf68] of RawUtf8 = (
    '', 'transport', 'tunnel', 'tunnel6', 'vti');
  ENUMOPENAPIPF69_TXT: array[TEnumOpenapipf69] of RawUtf8 = (
    '', 'ah', 'esp');
  ENUMOPENAPIPF70_TXT: array[TEnumOpenapipf70] of RawUtf8 = (
    '', 'fast', 'slow');
  ENUMOPENAPIPF71_TXT: array[TEnumOpenapipf71] of RawUtf8 = (
    '', 'l2', 'l2,l3', 'l2,l3,l4', 'l2,l4', 'l3', 'l3,l4', 'l4');
  ENUMOPENAPIPF72_TXT: array[TEnumOpenapipf72] of RawUtf8 = (
    '', 'failover', 'lacp', 'loadbalance', 'none', 'roundrobin');
  ENUMOPENAPIPF73_TXT: array[TEnumOpenapipf73] of RawUtf8 = (
    '', 'rfc3164', 'rfc5424');
  ENUMOPENAPIPF74_TXT: array[TEnumOpenapipf74] of RawUtf8 = (
    '', 'ipv4', 'ipv6');
  ENUMOPENAPIPF75_TXT: array[TEnumOpenapipf75] of RawUtf8 = (
    '', 'bzip2', 'gzip', 'none', 'xz', 'zstd');
  ENUMOPENAPIPF76_TXT: array[TEnumOpenapipf76] of RawUtf8 = (
    '', 'auto', 'inet', 'inet6');
  ENUMOPENAPIPF77_TXT: array[TEnumOpenapipf77] of RawUtf8 = (
    '', '', '10', '11', '12', '13', '14', '15', '16', '17', '3', '4', '5',
    '6', '7', '8', '9', 'omit');
  ENUMOPENAPIPF78_TXT: array[TEnumOpenapipf78] of RawUtf8 = (
    '', 'md5', 'sha1', 'sha256');
  ENUMOPENAPIPF79_TXT: array[TEnumOpenapipf79] of RawUtf8 = (
    '', 'peer', 'pool', 'server');
  ENUMOPENAPIPF80_TXT: array[TEnumOpenapipf80] of RawUtf8 = (
    '', 'SavedCfg');
  ENUMOPENAPIPF81_TXT: array[TEnumOpenapipf81] of RawUtf8 = (
    '', 'dhcp', 'none', 'static');
  ENUMOPENAPIPF82_TXT: array[TEnumOpenapipf82] of RawUtf8 = (
    '', '6rd', '6to4', 'dhcp6', 'none', 'slaac', 'staticv6', 'track6');
  ENUMOPENAPIPF83_TXT: array[TEnumOpenapipf83] of RawUtf8 = (
    '', 'inet', 'inet6');
  ENUMOPENAPIPF84_TXT: array[TEnumOpenapipf84] of RawUtf8 = (
    '', 'asym', 'no', 'yes');
  ENUMOPENAPIPF85_TXT: array[TEnumOpenapipf85] of RawUtf8 = (
    '', 'both', 'v4only', 'v6only');
  ENUMOPENAPIPF86_TXT: array[TEnumOpenapipf86] of RawUtf8 = (
    '', 'tap', 'tun');
  ENUMOPENAPIPF87_TXT: array[TEnumOpenapipf87] of RawUtf8 = (
    '', '1', '2', '3', '4', '5', 'none');
  ENUMOPENAPIPF88_TXT: array[TEnumOpenapipf88] of RawUtf8 = (
    '', 'p2p_tls');
  ENUMOPENAPIPF89_TXT: array[TEnumOpenapipf89] of RawUtf8 = (
    '', 'ping_exit', 'ping_restart');
  ENUMOPENAPIPF90_TXT: array[TEnumOpenapipf90] of RawUtf8 = (
    '', 'keepalive', 'ping');
  ENUMOPENAPIPF91_TXT: array[TEnumOpenapipf91] of RawUtf8 = (
    '', 'TCP', 'TCP4', 'TCP6', 'UDP', 'UDP4', 'UDP6');
  ENUMOPENAPIPF92_TXT: array[TEnumOpenapipf92] of RawUtf8 = (
    '', 'basic', 'none', 'ntlm');
  ENUMOPENAPIPF93_TXT: array[TEnumOpenapipf93] of RawUtf8 = (
    '', 'auth', 'crypt');
  ENUMOPENAPIPF94_TXT: array[TEnumOpenapipf94] of RawUtf8 = (
    '', '0', '1', '2', 'default');
  ENUMOPENAPIPF95_TXT: array[TEnumOpenapipf95] of RawUtf8 = (
    '', 'net30', 'subnet');
  ENUMOPENAPIPF96_TXT: array[TEnumOpenapipf96] of RawUtf8 = (
    '', 'p2p_tls', 'server_tls', 'server_tls_user', 'server_user');
  ENUMOPENAPIPF97_TXT: array[TEnumOpenapipf97] of RawUtf8 = (
    '', 'bitmask', 'random', 'random sticky-address', 'round-robin', 'round-robin sticky-address',
    'source-hash');
  ENUMOPENAPIPF98_TXT: array[TEnumOpenapipf98] of RawUtf8 = (
    '', 'ah', 'esp', 'gre', 'icmp', 'igmp', 'ipv6', 'ospf', 'pim', 'tcp',
    'tcp/udp', 'udp');
  ENUMOPENAPIPF99_TXT: array[TEnumOpenapipf99] of RawUtf8 = (
    '', 'advanced', 'automatic', 'disabled', 'hybrid');
  ENUMOPENAPIPF100_TXT: array[TEnumOpenapipf100] of RawUtf8 = (
    '', 'disable', 'enable', 'purenat');
  ENUMOPENAPIPF101_TXT: array[TEnumOpenapipf101] of RawUtf8 = (
    '', 'allow', 'deny');
  ENUMOPENAPIPF102_TXT: array[TEnumOpenapipf102] of RawUtf8 = (
    '', 'sha256', 'sha384', 'sha512');
  ENUMOPENAPIPF103_TXT: array[TEnumOpenapipf103] of RawUtf8 = (
    '', 'descr', 'id', 'if');
  ENUMOPENAPIPF104_TXT: array[TEnumOpenapipf104] of RawUtf8 = (
    '', '', 'down', 'none');
  ENUMOPENAPIPF105_TXT: array[TEnumOpenapipf105] of RawUtf8 = (
    '', 'down', 'downlatency', 'downloss', 'downlosslatency');
  ENUMOPENAPIPF106_TXT: array[TEnumOpenapipf106] of RawUtf8 = (
    '', 'both', 'enabled');
  ENUMOPENAPIPF107_TXT: array[TEnumOpenapipf107] of RawUtf8 = (
    '', 'restart', 'start', 'stop');
  ENUMOPENAPIPF108_TXT: array[TEnumOpenapipf108] of RawUtf8 = (
    '', 'local', 'remote');
  ENUMOPENAPIPF109_TXT: array[TEnumOpenapipf109] of RawUtf8 = (
    '', '%', 'Gb', 'Kb', 'Mb', 'b');
  ENUMOPENAPIPF110_TXT: array[TEnumOpenapipf110] of RawUtf8 = (
    '', 'CBQ', 'CODELQ', 'FAIRQ', 'HFSC', 'PRIQ');
  ENUMOPENAPIPF111_TXT: array[TEnumOpenapipf111] of RawUtf8 = (
    '', 'codel', 'droptail', 'gred', 'pie', 'red');
  ENUMOPENAPIPF112_TXT: array[TEnumOpenapipf112] of RawUtf8 = (
    '', 'dstaddress', 'none', 'srcaddress');
  ENUMOPENAPIPF113_TXT: array[TEnumOpenapipf113] of RawUtf8 = (
    '', 'fifo', 'fq_codel', 'fq_pie', 'prio', 'qfq', 'rr', 'wf2q+');
  ENUMOPENAPIPF114_TXT: array[TEnumOpenapipf114] of RawUtf8 = (
    '', 'Kb', 'Mb', 'b');
  ENUMOPENAPIPF115_TXT: array[TEnumOpenapipf115] of RawUtf8 = (
    '', 'mcast', 'ucast');
  ENUMOPENAPIPF116_TXT: array[TEnumOpenapipf116] of RawUtf8 = (
    '', 'carp', 'ipalias', 'other', 'proxyarp');
  ENUMOPENAPIPF117_TXT: array[TEnumOpenapipf117] of RawUtf8 = (
    '', 'network', 'single');
  ENUMOPENAPIPF118_TXT: array[TEnumOpenapipf118] of RawUtf8 = (
    '', 'all', 'none', 'unassigned');
  ENUMOPENAPIPF119_TXT: array[TEnumOpenapipf119] of RawUtf8 = (
    '', 'SORT_ASC', 'SORT_DESC');
  ENUMOPENAPIPF120_TXT: array[TEnumOpenapipf120] of RawUtf8 = (
    '', 'SORT_FLAG_CASE', 'SORT_LOCALE_STRING', 'SORT_NATURAL', 'SORT_NUMERIC',
    'SORT_REGULAR', 'SORT_STRING');

type

{ ************ Main TOpenapipfClient Class }

  TOpenapipfClient = class
  private
    fClient: IJsonClient;
  public

    // initialize this Client with an associated HTTP/JSON request
    constructor Create(const aClient: IJsonClient);

    // AUTH methods
    procedure PostAuthJWTEndpoint();
    procedure DeleteAuthKeyEndpoint(const Id: variant);
    procedure PostAuthKeyEndpoint();
    procedure DeleteAuthKeysEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetAuthKeysEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);

    // DIAGNOSTICS methods
    procedure DeleteDiagnosticsARPTableEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetDiagnosticsARPTableEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteDiagnosticsARPTableEntryEndpoint(const Id: variant);
    procedure GetDiagnosticsARPTableEntryEndpoint(const Id: variant);
    procedure PostDiagnosticsCommandPromptEndpoint();
    procedure DeleteDiagnosticsConfigHistoryRevisionEndpoint(const Id: variant);
    procedure GetDiagnosticsConfigHistoryRevisionEndpoint(const Id: variant);
    procedure DeleteDiagnosticsConfigHistoryRevisionsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetDiagnosticsConfigHistoryRevisionsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PostDiagnosticsHaltSystemEndpoint();
    procedure PostDiagnosticsRebootEndpoint();

    // FIREWALL methods
    procedure GetFirewallAdvancedSettingsEndpoint();
    procedure PatchFirewallAdvancedSettingsEndpoint();
    procedure DeleteFirewallAliasEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetFirewallAliasEndpoint(const Id: variant);
    procedure PatchFirewallAliasEndpoint();
    procedure PostFirewallAliasEndpoint();
    procedure DeleteFirewallAliasesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetFirewallAliasesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutFirewallAliasesEndpoint(const Payload: variant);
    procedure GetFirewallApplyEndpoint();
    procedure PostFirewallApplyEndpoint();
    procedure DeleteFirewallNATOneToOneMappingEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetFirewallNATOneToOneMappingEndpoint(const Id: variant);
    procedure PatchFirewallNATOneToOneMappingEndpoint();
    procedure PostFirewallNATOneToOneMappingEndpoint();
    procedure DeleteFirewallNATOneToOneMappingsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetFirewallNATOneToOneMappingsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutFirewallNATOneToOneMappingsEndpoint(const Payload: variant);
    procedure DeleteFirewallNATOutboundMappingEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetFirewallNATOutboundMappingEndpoint(const Id: variant);
    procedure PatchFirewallNATOutboundMappingEndpoint();
    procedure PostFirewallNATOutboundMappingEndpoint();
    procedure DeleteFirewallNATOutboundMappingsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetFirewallNATOutboundMappingsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutFirewallNATOutboundMappingsEndpoint(const Payload: variant);
    procedure GetFirewallNATOutboundModeEndpoint();
    procedure PatchFirewallNATOutboundModeEndpoint();
    procedure DeleteFirewallNATPortForwardEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetFirewallNATPortForwardEndpoint(const Id: variant);
    procedure PatchFirewallNATPortForwardEndpoint();
    procedure PostFirewallNATPortForwardEndpoint();
    procedure DeleteFirewallNATPortForwardsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetFirewallNATPortForwardsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutFirewallNATPortForwardsEndpoint(const Payload: variant);
    procedure DeleteFirewallRuleEndpoint(const Id: variant);
    procedure GetFirewallRuleEndpoint(const Id: variant);
    procedure PatchFirewallRuleEndpoint();
    procedure PostFirewallRuleEndpoint();
    procedure DeleteFirewallRulesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetFirewallRulesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutFirewallRulesEndpoint(const Payload: variant);
    procedure DeleteFirewallScheduleEndpoint(const Id: variant);
    procedure GetFirewallScheduleEndpoint(const Id: variant);
    procedure PatchFirewallScheduleEndpoint();
    procedure PostFirewallScheduleEndpoint();
    procedure DeleteFirewallScheduleTimeRangeEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetFirewallScheduleTimeRangeEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchFirewallScheduleTimeRangeEndpoint();
    procedure PostFirewallScheduleTimeRangeEndpoint();
    procedure DeleteFirewallSchedulesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetFirewallSchedulesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutFirewallSchedulesEndpoint(const Payload: variant);
    procedure DeleteFirewallStateEndpoint_deprecated(const Id: variant);
    procedure GetFirewallStateEndpoint_deprecated(const Id: variant);
    procedure DeleteFirewallStatesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetFirewallStatesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetFirewallStatesSizeEndpoint();
    procedure PatchFirewallStatesSizeEndpoint();
    procedure DeleteFirewallTrafficShaperEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetFirewallTrafficShaperEndpoint(const Id: variant);
    procedure PatchFirewallTrafficShaperEndpoint();
    procedure PostFirewallTrafficShaperEndpoint();
    procedure DeleteFirewallTrafficShaperLimiterEndpoint(const Id: variant;
      Apply: boolean = false);
    procedure GetFirewallTrafficShaperLimiterEndpoint(const Id: variant);
    procedure PatchFirewallTrafficShaperLimiterEndpoint();
    procedure PostFirewallTrafficShaperLimiterEndpoint();
    procedure DeleteFirewallTrafficShaperLimiterBandwidthEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetFirewallTrafficShaperLimiterBandwidthEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchFirewallTrafficShaperLimiterBandwidthEndpoint();
    procedure PostFirewallTrafficShaperLimiterBandwidthEndpoint();
    procedure DeleteFirewallTrafficShaperLimiterQueueEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetFirewallTrafficShaperLimiterQueueEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchFirewallTrafficShaperLimiterQueueEndpoint();
    procedure PostFirewallTrafficShaperLimiterQueueEndpoint();
    procedure GetFirewallTrafficShaperLimitersEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutFirewallTrafficShaperLimitersEndpoint(const Payload: variant);
    procedure DeleteFirewallTrafficShaperQueueEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetFirewallTrafficShaperQueueEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchFirewallTrafficShaperQueueEndpoint();
    procedure PostFirewallTrafficShaperQueueEndpoint();
    procedure DeleteFirewallTrafficShapersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetFirewallTrafficShapersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutFirewallTrafficShapersEndpoint(const Payload: variant);
    procedure DeleteFirewallVirtualIPEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetFirewallVirtualIPEndpoint(const Id: variant);
    procedure PatchFirewallVirtualIPEndpoint();
    procedure PostFirewallVirtualIPEndpoint();
    procedure GetFirewallVirtualIPApplyEndpoint();
    procedure PostFirewallVirtualIPApplyEndpoint();
    procedure DeleteFirewallVirtualIPsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetFirewallVirtualIPsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);

    // GRAPHQL methods
    procedure PostGraphQLEndpoint();

    // INTERFACE methods
    procedure DeleteNetworkInterfaceEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetNetworkInterfaceEndpoint(const Id: variant);
    procedure PatchNetworkInterfaceEndpoint();
    procedure PostNetworkInterfaceEndpoint();
    procedure GetInterfaceApplyEndpoint();
    procedure PostInterfaceApplyEndpoint();
    procedure GetInterfaceAvailableInterfacesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteInterfaceBridgeEndpoint(const Id: variant);
    procedure GetInterfaceBridgeEndpoint(const Id: variant);
    procedure PatchInterfaceBridgeEndpoint();
    procedure PostInterfaceBridgeEndpoint();
    procedure GetInterfaceBridgesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteInterfaceGREEndpoint(const Id: variant);
    procedure GetInterfaceGREEndpoint(const Id: variant);
    procedure PatchInterfaceGREEndpoint();
    procedure PostInterfaceGREEndpoint();
    procedure DeleteInterfaceGREsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetInterfaceGREsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteInterfaceGroupEndpoint(const Id: variant);
    procedure GetInterfaceGroupEndpoint(const Id: variant);
    procedure PatchInterfaceGroupEndpoint();
    procedure PostInterfaceGroupEndpoint();
    procedure DeleteInterfaceGroupsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetInterfaceGroupsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutInterfaceGroupsEndpoint(const Payload: variant);
    procedure DeleteInterfaceLAGGEndpoint(const Id: variant);
    procedure GetInterfaceLAGGEndpoint(const Id: variant);
    procedure PatchInterfaceLAGGEndpoint();
    procedure PostInterfaceLAGGEndpoint();
    procedure DeleteInterfaceLAGGsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetInterfaceLAGGsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteInterfaceVLANEndpoint(const Id: variant);
    procedure GetInterfaceVLANEndpoint(const Id: variant);
    procedure PatchInterfaceVLANEndpoint();
    procedure PostInterfaceVLANEndpoint();
    procedure DeleteInterfaceVLANsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetInterfaceVLANsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteNetworkInterfacesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetNetworkInterfacesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);

    // ROUTING methods
    procedure GetRoutingApplyEndpoint();
    procedure PostRoutingApplyEndpoint();
    procedure DeleteRoutingGatewayEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetRoutingGatewayEndpoint(const Id: variant);
    procedure PatchRoutingGatewayEndpoint();
    procedure PostRoutingGatewayEndpoint();
    procedure GetRoutingGatewayDefaultEndpoint();
    procedure PatchRoutingGatewayDefaultEndpoint();
    procedure DeleteRoutingGatewayGroupEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetRoutingGatewayGroupEndpoint(const Id: variant);
    procedure PatchRoutingGatewayGroupEndpoint();
    procedure PostRoutingGatewayGroupEndpoint();
    procedure DeleteRoutingGatewayGroupPriorityEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetRoutingGatewayGroupPriorityEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchRoutingGatewayGroupPriorityEndpoint();
    procedure PostRoutingGatewayGroupPriorityEndpoint();
    procedure DeleteRoutingGatewayGroupsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetRoutingGatewayGroupsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteRoutingGatewaysEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetRoutingGatewaysEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteRoutingStaticRouteEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetRoutingStaticRouteEndpoint(const Id: variant);
    procedure PatchRoutingStaticRouteEndpoint();
    procedure PostRoutingStaticRouteEndpoint();
    procedure DeleteRoutingStaticRoutesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetRoutingStaticRoutesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);

    // SERVICES methods
    procedure DeleteServicesACMEAccountKeyEndpoint(const Id: variant);
    procedure GetServicesACMEAccountKeyEndpoint(const Id: variant);
    procedure PatchServicesACMEAccountKeyEndpoint();
    procedure PostServicesACMEAccountKeyEndpoint();
    procedure PostServicesACMEAccountKeyRegisterEndpoint();
    procedure GetServicesACMEAccountKeyRegistrationsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteServicesACMEAccountKeysEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetServicesACMEAccountKeysEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesACMEAccountKeysEndpoint(const Payload: variant);
    procedure DeleteServicesACMECertificateEndpoint(const Id: variant);
    procedure GetServicesACMECertificateEndpoint(const Id: variant);
    procedure PatchServicesACMECertificateEndpoint();
    procedure PostServicesACMECertificateEndpoint();
    procedure DeleteServicesACMECertificateActionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesACMECertificateActionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesACMECertificateActionEndpoint();
    procedure PostServicesACMECertificateActionEndpoint();
    procedure DeleteServicesACMECertificateDomainEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesACMECertificateDomainEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesACMECertificateDomainEndpoint();
    procedure PostServicesACMECertificateDomainEndpoint();
    procedure GetServicesACMECertificateIssuancesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PostServicesACMECertificateIssueEndpoint();
    procedure PostServicesACMECertificateRenewEndpoint();
    procedure GetServicesACMECertificateRenewalsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteServicesACMECertificatesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetServicesACMECertificatesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesACMECertificatesEndpoint(const Payload: variant);
    procedure GetServicesACMESettingsEndpoint();
    procedure PatchServicesACMESettingsEndpoint();
    procedure DeleteServicesBINDAccessListEndpoint(const Id: variant);
    procedure GetServicesBINDAccessListEndpoint(const Id: variant);
    procedure PatchServicesBINDAccessListEndpoint();
    procedure PostServicesBINDAccessListEndpoint();
    procedure DeleteServicesBINDAccessListEntryEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesBINDAccessListEntryEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesBINDAccessListEntryEndpoint();
    procedure PostServicesBINDAccessListEntryEndpoint();
    procedure DeleteServicesBINDAccessListsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetServicesBINDAccessListsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesBINDAccessListsEndpoint(const Payload: variant);
    procedure GetServicesBINDSettingsEndpoint();
    procedure PatchServicesBINDSettingsEndpoint();
    procedure DeleteServicesBINDSyncRemoteHostEndpoint(const Id: variant);
    procedure GetServicesBINDSyncRemoteHostEndpoint(const Id: variant);
    procedure PatchServicesBINDSyncRemoteHostEndpoint();
    procedure PostServicesBINDSyncRemoteHostEndpoint();
    procedure DeleteServicesBINDSyncRemoteHostsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetServicesBINDSyncRemoteHostsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesBINDSyncRemoteHostsEndpoint(const Payload: variant);
    procedure GetServicesBINDSyncSettingsEndpoint();
    procedure PatchServicesBINDSyncSettingsEndpoint();
    procedure DeleteServicesBINDViewEndpoint(const Id: variant);
    procedure GetServicesBINDViewEndpoint(const Id: variant);
    procedure PatchServicesBINDViewEndpoint();
    procedure PostServicesBINDViewEndpoint();
    procedure DeleteServicesBINDViewsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetServicesBINDViewsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesBINDViewsEndpoint(const Payload: variant);
    procedure DeleteServicesBINDZoneEndpoint(const Id: variant);
    procedure GetServicesBINDZoneEndpoint(const Id: variant);
    procedure PatchServicesBINDZoneEndpoint();
    procedure PostServicesBINDZoneEndpoint();
    procedure DeleteServicesBINDZoneRecordEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesBINDZoneRecordEndpoint(const ParentId: variant; const Id: variant);
    procedure PatchServicesBINDZoneRecordEndpoint();
    procedure PostServicesBINDZoneRecordEndpoint();
    procedure DeleteServicesBINDZonesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetServicesBINDZonesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesBINDZonesEndpoint(const Payload: variant);
    procedure DeleteServicesCronJobEndpoint(const Id: variant);
    procedure GetServicesCronJobEndpoint(const Id: variant);
    procedure PatchServicesCronJobEndpoint();
    procedure PostServicesCronJobEndpoint();
    procedure DeleteServicesCronJobsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetServicesCronJobsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesCronJobsEndpoint(const Payload: variant);
    procedure GetServicesDHCPServerEndpoint(const Id: variant);
    procedure PatchServicesDHCPServerEndpoint();
    procedure DeleteServicesDHCPServerAddressPoolEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetServicesDHCPServerAddressPoolEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesDHCPServerAddressPoolEndpoint();
    procedure PostServicesDHCPServerAddressPoolEndpoint();
    procedure GetServicesDHCPServerApplyEndpoint();
    procedure PostServicesDHCPServerApplyEndpoint();
    procedure PatchServicesDHCPServerBackendEndpoint();
    procedure DeleteServicesDHCPServerCustomOptionEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetServicesDHCPServerCustomOptionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesDHCPServerCustomOptionEndpoint();
    procedure PostServicesDHCPServerCustomOptionEndpoint();
    procedure DeleteServicesDHCPServerStaticMappingEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetServicesDHCPServerStaticMappingEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesDHCPServerStaticMappingEndpoint();
    procedure PostServicesDHCPServerStaticMappingEndpoint();
    procedure GetServicesDHCPServersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesDHCPServersEndpoint(const Payload: variant);
    procedure GetServicesDNSForwarderApplyEndpoint();
    procedure PostServicesDNSForwarderApplyEndpoint();
    procedure DeleteServicesDNSForwarderHostOverrideEndpoint(const Id: variant;
      Apply: boolean = false);
    procedure GetServicesDNSForwarderHostOverrideEndpoint(const Id: variant);
    procedure PatchServicesDNSForwarderHostOverrideEndpoint();
    procedure PostServicesDNSForwarderHostOverrideEndpoint();
    procedure DeleteServicesDNSForwarderHostOverrideAliasEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetServicesDNSForwarderHostOverrideAliasEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesDNSForwarderHostOverrideAliasEndpoint();
    procedure PostServicesDNSForwarderHostOverrideAliasEndpoint();
    procedure DeleteServicesDNSForwarderHostOverridesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetServicesDNSForwarderHostOverridesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesDNSForwarderHostOverridesEndpoint(const Payload: variant);
    procedure DeleteServicesDNSResolverAccessListEndpoint(const Id: variant;
      Apply: boolean = false);
    procedure GetServicesDNSResolverAccessListEndpoint(const Id: variant);
    procedure PatchServicesDNSResolverAccessListEndpoint();
    procedure PostServicesDNSResolverAccessListEndpoint();
    procedure DeleteServicesDNSResolverAccessListNetworkEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetServicesDNSResolverAccessListNetworkEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesDNSResolverAccessListNetworkEndpoint();
    procedure PostServicesDNSResolverAccessListNetworkEndpoint();
    procedure DeleteServicesDNSResolverAccessListsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetServicesDNSResolverAccessListsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesDNSResolverAccessListsEndpoint(const Payload: variant);
    procedure GetServicesDNSResolverApplyEndpoint();
    procedure PostServicesDNSResolverApplyEndpoint();
    procedure DeleteServicesDNSResolverDomainOverrideEndpoint(const Id: variant;
      Apply: boolean = false);
    procedure GetServicesDNSResolverDomainOverrideEndpoint(const Id: variant);
    procedure PatchServicesDNSResolverDomainOverrideEndpoint();
    procedure PostServicesDNSResolverDomainOverrideEndpoint();
    procedure DeleteServicesDNSResolverDomainOverridesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetServicesDNSResolverDomainOverridesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesDNSResolverDomainOverridesEndpoint(const Payload: variant);
    procedure DeleteServicesDNSResolverHostOverrideEndpoint(const Id: variant;
      Apply: boolean = false);
    procedure GetServicesDNSResolverHostOverrideEndpoint(const Id: variant);
    procedure PatchServicesDNSResolverHostOverrideEndpoint();
    procedure PostServicesDNSResolverHostOverrideEndpoint();
    procedure DeleteServicesDNSResolverHostOverrideAliasEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetServicesDNSResolverHostOverrideAliasEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesDNSResolverHostOverrideAliasEndpoint();
    procedure PostServicesDNSResolverHostOverrideAliasEndpoint();
    procedure DeleteServicesDNSResolverHostOverridesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetServicesDNSResolverHostOverridesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesDNSResolverHostOverridesEndpoint(const Payload: variant);
    procedure GetServicesDNSResolverSettingsEndpoint();
    procedure PatchServicesDNSResolverSettingsEndpoint();
    procedure GetServicesHAProxyApplyEndpoint();
    procedure PostServicesHAProxyApplyEndpoint();
    procedure DeleteServicesHAProxyBackendEndpoint(const Id: variant);
    procedure GetServicesHAProxyBackendEndpoint(const Id: variant);
    procedure PatchServicesHAProxyBackendEndpoint();
    procedure PostServicesHAProxyBackendEndpoint();
    procedure DeleteServicesHAProxyBackendACLEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesHAProxyBackendACLEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesHAProxyBackendACLEndpoint();
    procedure PostServicesHAProxyBackendACLEndpoint();
    procedure DeleteServicesHAProxyBackendActionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesHAProxyBackendActionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesHAProxyBackendActionEndpoint();
    procedure PostServicesHAProxyBackendActionEndpoint();
    procedure DeleteServicesHAProxyBackendErrorFileEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesHAProxyBackendErrorFileEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesHAProxyBackendErrorFileEndpoint();
    procedure PostServicesHAProxyBackendErrorFileEndpoint();
    procedure DeleteServicesHAProxyBackendServerEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesHAProxyBackendServerEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesHAProxyBackendServerEndpoint();
    procedure PostServicesHAProxyBackendServerEndpoint();
    procedure DeleteServicesHAProxyBackendsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetServicesHAProxyBackendsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesHAProxyBackendsEndpoint(const Payload: variant);
    procedure DeleteServicesHAProxyFileEndpoint(const Id: variant);
    procedure GetServicesHAProxyFileEndpoint(const Id: variant);
    procedure PatchServicesHAProxyFileEndpoint();
    procedure PostServicesHAProxyFileEndpoint();
    procedure DeleteServicesHAProxyFiles(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetServicesHAProxyFiles(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesHAProxyFiles(const Payload: variant);
    procedure DeleteServicesHAProxyFrontendEndpoint(const Id: variant);
    procedure GetServicesHAProxyFrontendEndpoint(const Id: variant);
    procedure PatchServicesHAProxyFrontendEndpoint();
    procedure PostServicesHAProxyFrontendEndpoint();
    procedure DeleteServicesHAProxyFrontendACLEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesHAProxyFrontendACLEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesHAProxyFrontendACLEndpoint();
    procedure PostServicesHAProxyFrontendACLEndpoint();
    procedure DeleteServicesHAProxyFrontendActionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesHAProxyFrontendActionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesHAProxyFrontendActionEndpoint();
    procedure PostServicesHAProxyFrontendActionEndpoint();
    procedure DeleteServicesHAProxyFrontendAddressEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesHAProxyFrontendAddressEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesHAProxyFrontendAddressEndpoint();
    procedure PostServicesHAProxyFrontendAddressEndpoint();
    procedure DeleteServicesHAProxyFrontendErrorFileEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetServicesHAProxyFrontendErrorFileEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchServicesHAProxyFrontendErrorFileEndpoint();
    procedure PostServicesHAProxyFrontendErrorFileEndpoint();
    procedure DeleteServicesHAProxyFrontendsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetServicesHAProxyFrontendsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesHAProxyFrontendsEndpoint(const Payload: variant);
    procedure GetServicesHAProxySettingsEndpoint();
    procedure PatchServicesHAProxySettingsEndpoint();
    procedure DeleteServicesHAProxySettingsDNSResolverEndpoint(const Id: variant);
    procedure GetServicesHAProxySettingsDNSResolverEndpoint(const Id: variant);
    procedure PatchServicesHAProxySettingsDNSResolverEndpoint();
    procedure PostServicesHAProxySettingsDNSResolverEndpoint();
    procedure DeleteServicesHAProxySettingsEmailMailerEndpoint(const Id: variant);
    procedure GetServicesHAProxySettingsEmailMailerEndpoint(const Id: variant);
    procedure PatchServicesHAProxySettingsEmailMailerEndpoint();
    procedure PostServicesHAProxySettingsEmailMailerEndpoint();
    procedure GetServicesNTPSettingsEndpoint();
    procedure PatchServicesNTPSettingsEndpoint();
    procedure DeleteServicesNTPTimeServerEndpoint(const Id: variant);
    procedure GetServicesNTPTimeServerEndpoint(const Id: variant);
    procedure PatchServicesNTPTimeServerEndpoint();
    procedure PostServicesNTPTimeServerEndpoint();
    procedure DeleteServicesNTPTimeServersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetServicesNTPTimeServersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesNTPTimeServersEndpoint(const Payload: variant);
    procedure DeleteServicesServiceWatchdogEndpoint(const Id: variant);
    procedure GetServicesServiceWatchdogEndpoint(const Id: variant);
    procedure PatchServicesServiceWatchdogEndpoint();
    procedure PostServicesServiceWatchdogEndpoint();
    procedure DeleteServicesServiceWatchdogsEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetServicesServiceWatchdogsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutServicesServiceWatchdogsEndpoint(const Payload: variant);
    procedure GetServicesSSHEndpoint();
    procedure PatchServicesSSHEndpoint();
    procedure PostServicesWakeOnLANSendEndpoint();

    // STATUS methods
    procedure GetStatusCARPEndpoint();
    procedure PatchStatusCARPEndpoint();
    procedure DeleteStatusDHCPServerLeasesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetStatusDHCPServerLeasesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetStatusGatewaysEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetStatusInterfacesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetStatusIPsecChildSAEndpoint(const ParentId: variant; const Id: variant);
    procedure GetStatusIPsecSAsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetStatusLogsDHCPEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetStatusLogsFirewallEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetStatusLogsSettingsEndpoint();
    procedure PatchStatusLogsSettingsEndpoint();
    procedure GetStatusLogsSystemEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetStatusOpenVPNClientsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteStatusOpenVPNServerConnectionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetStatusOpenVPNServerConnectionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetStatusOpenVPNServerRouteEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetStatusOpenVPNServersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PostStatusServiceEndpoint();
    procedure GetStatusServicesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetStatusSystemEndpoint();

    // SYSTEM methods
    procedure DeleteSystemCertificateEndpoint(const Id: variant);
    procedure GetSystemCertificateEndpoint(const Id: variant);
    procedure PatchSystemCertificateEndpoint();
    procedure PostSystemCertificateEndpoint();
    procedure PostSystemCertificateGenerateEndpoint();
    procedure PostSystemCertificatePKCS12ExportEndpoint();
    procedure PostSystemCertificateRenewEndpoint();
    procedure PostSystemCertificateSigningRequestEndpoint();
    procedure PostSystemCertificateSigningRequestSignEndpoint();
    procedure DeleteSystemCertificateAuthoritiesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0);
    procedure GetSystemCertificateAuthoritiesEndpoint(const Query: variant;
      Limit: integer = 0; Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil;
      const SortOrder: TEnumOpenapipf119 = eo119None; const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteSystemCertificateAuthorityEndpoint(const Id: variant);
    procedure GetSystemCertificateAuthorityEndpoint(const Id: variant);
    procedure PatchSystemCertificateAuthorityEndpoint();
    procedure PostSystemCertificateAuthorityEndpoint();
    procedure PostSystemCertificateAuthorityGenerateEndpoint();
    procedure PostSystemCertificateAuthorityRenewEndpoint();
    procedure DeleteSystemCertificatesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetSystemCertificatesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetSystemConsoleEndpoint();
    procedure PatchSystemConsoleEndpoint();
    procedure DeleteSystemCRLEndpoint(const Id: variant);
    procedure GetSystemCRLEndpoint(const Id: variant);
    procedure PatchSystemCRLEndpoint();
    procedure PostSystemCRLEndpoint();
    procedure DeleteSystemCRLRevokedCertificateEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetSystemCRLRevokedCertificateEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchSystemCRLRevokedCertificateEndpoint();
    procedure PostSystemCRLRevokedCertificateEndpoint();
    procedure DeleteSystemCRLsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetSystemCRLsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetSystemDNSEndpoint();
    procedure PatchSystemDNSEndpoint();
    procedure GetSystemHostnameEndpoint();
    procedure PatchSystemHostnameEndpoint();
    procedure GetSystemNotificationsEmailSettingsEndpoint();
    procedure PatchSystemNotificationsEmailSettingsEndpoint();
    procedure DeleteSystemPackageEndpoint(const Id: variant);
    procedure GetSystemPackageEndpoint(const Id: variant);
    procedure PostSystemPackageEndpoint();
    procedure GetSystemPackageAvailableEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteSystemPackagesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetSystemPackagesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteSystemRESTAPIAccessListEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetSystemRESTAPIAccessListEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutSystemRESTAPIAccessListEndpoint(const Payload: variant);
    procedure DeleteSystemRESTAPIAccessListEntryEndpoint(const Id: variant);
    procedure GetSystemRESTAPIAccessListEntryEndpoint(const Id: variant);
    procedure PatchSystemRESTAPIAccessListEntryEndpoint();
    procedure PostSystemRESTAPIAccessListEntryEndpoint();
    procedure GetSystemRESTAPISettingsEndpoint();
    procedure PatchSystemRESTAPISettingsEndpoint();
    procedure PostSystemRESTAPISettingsSyncEndpoint();
    procedure GetSystemRESTAPIVersionEndpoint();
    procedure PatchSystemRESTAPIVersionEndpoint();
    procedure DeleteSystemTunableEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetSystemTunableEndpoint(const Id: variant);
    procedure PatchSystemTunableEndpoint();
    procedure PostSystemTunableEndpoint();
    procedure DeleteSystemTunablesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetSystemTunablesEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutSystemTunablesEndpoint(const Payload: variant);
    procedure GetSystemVersionEndpoint();
    procedure GetSystemWebGUISettingsEndpoint();
    procedure PatchSystemWebGUISettingsEndpoint();

    // USER methods
    procedure DeleteUserEndpoint(const Id: variant);
    procedure GetUserEndpoint(const Id: variant);
    procedure PatchUserEndpoint();
    procedure PostUserEndpoint();
    procedure DeleteUserAuthServerEndpoint(const Id: variant);
    procedure GetUserAuthServerEndpoint(const Id: variant);
    procedure PatchUserAuthServerEndpoint();
    procedure PostUserAuthServerEndpoint();
    procedure DeleteUserAuthServersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetUserAuthServersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutUserAuthServersEndpoint(const Payload: variant);
    procedure DeleteUserGroupEndpoint(const Id: variant);
    procedure GetUserGroupEndpoint(const Id: variant);
    procedure PatchUserGroupEndpoint();
    procedure PostUserGroupEndpoint();
    procedure DeleteUserGroupsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetUserGroupsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutUserGroupsEndpoint(const Payload: variant);
    procedure DeleteUsersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetUsersEndpoint(const Query: variant; Limit: integer = 0; Offset: integer = 0;
      const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);

    // VPN methods
    procedure GetVPNIPsecApplyEndpoint();
    procedure PostVPNIPsecApplyEndpoint();
    procedure DeleteVPNIPsecPhase1Endpoint(const Id: variant; Apply: boolean = false);
    procedure GetVPNIPsecPhase1Endpoint(const Id: variant);
    procedure PatchVPNIPsecPhase1Endpoint();
    procedure PostVPNIPsecPhase1Endpoint();
    procedure DeleteVPNIPsecPhase1EncryptionEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetVPNIPsecPhase1EncryptionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchVPNIPsecPhase1EncryptionEndpoint();
    procedure PostVPNIPsecPhase1EncryptionEndpoint();
    procedure DeleteVPNIPsecPhase1sEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetVPNIPsecPhase1sEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutVPNIPsecPhase1sEndpoint(const Payload: variant);
    procedure DeleteVPNIPsecPhase2Endpoint(const Id: variant; Apply: boolean = false);
    procedure GetVPNIPsecPhase2Endpoint(const Id: variant);
    procedure PatchVPNIPsecPhase2Endpoint();
    procedure PostVPNIPsecPhase2Endpoint();
    procedure DeleteVPNIPsecPhase2EncryptionEndpoint(const ParentId: variant;
      const Id: variant; Apply: boolean = false);
    procedure GetVPNIPsecPhase2EncryptionEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchVPNIPsecPhase2EncryptionEndpoint();
    procedure PostVPNIPsecPhase2EncryptionEndpoint();
    procedure DeleteVPNIPsecPhase2sEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetVPNIPsecPhase2sEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutVPNIPsecPhase2sEndpoint(const Payload: variant);
    procedure DeleteVPNOpenVPNClientEndpoint(const Id: variant);
    procedure GetVPNOpenVPNClientEndpoint(const Id: variant);
    procedure PatchVPNOpenVPNClientEndpoint();
    procedure PostVPNOpenVPNClientEndpoint();
    procedure DeleteVPNOpenVPNClientsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetVPNOpenVPNClientsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteVPNOpenVPNCSOEndpoint(const Id: variant);
    procedure GetVPNOpenVPNCSOEndpoint(const Id: variant);
    procedure PatchVPNOpenVPNCSOEndpoint();
    procedure PostVPNOpenVPNCSOEndpoint();
    procedure DeleteVPNOpenVPNCSOsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetVPNOpenVPNCSOsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure DeleteVPNOpenVPNServerEndpoint(const Id: variant);
    procedure GetVPNOpenVPNServerEndpoint(const Id: variant);
    procedure PatchVPNOpenVPNServerEndpoint();
    procedure PostVPNOpenVPNServerEndpoint();
    procedure DeleteVPNOpenVPNServersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetVPNOpenVPNServersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure GetVPNWireGuardApplyEndpoint();
    procedure PostVPNWireGuardApplyEndpoint();
    procedure DeleteVPNWireGuardPeerEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetVPNWireGuardPeerEndpoint(const Id: variant);
    procedure PatchVPNWireGuardPeerEndpoint();
    procedure PostVPNWireGuardPeerEndpoint();
    procedure DeleteVPNWireGuardPeerAllowedIPEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetVPNWireGuardPeerAllowedIPEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchVPNWireGuardPeerAllowedIPEndpoint();
    procedure PostVPNWireGuardPeerAllowedIPEndpoint();
    procedure DeleteVPNWireGuardPeersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetVPNWireGuardPeersEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutVPNWireGuardPeersEndpoint(const Payload: variant);
    procedure GetVPNWireGuardSettingsEndpoint();
    procedure PatchVPNWireGuardSettingsEndpoint();
    procedure DeleteVPNWireGuardTunnelEndpoint(const Id: variant; Apply: boolean = false);
    procedure GetVPNWireGuardTunnelEndpoint(const Id: variant);
    procedure PatchVPNWireGuardTunnelEndpoint();
    procedure PostVPNWireGuardTunnelEndpoint();
    procedure DeleteVPNWireGuardTunnelAddressEndpoint(const ParentId: variant;
      const Id: variant);
    procedure GetVPNWireGuardTunnelAddressEndpoint(const ParentId: variant;
      const Id: variant);
    procedure PatchVPNWireGuardTunnelAddressEndpoint();
    procedure PostVPNWireGuardTunnelAddressEndpoint();
    procedure DeleteVPNWireGuardTunnelsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0);
    procedure GetVPNWireGuardTunnelsEndpoint(const Query: variant; Limit: integer = 0;
      Offset: integer = 0; const SortBy: TRawUtf8DynArray = nil; const SortOrder: TEnumOpenapipf119 = eo119None;
      const SortFlags: TEnumOpenapipf120 = eo120None);
    procedure PutVPNWireGuardTunnelsEndpoint(const Payload: variant);

    // access to the associated HTTP/JSON client instance
    property JsonClient: IJsonClient
      read fClient write fClient;
  end;


implementation



{ ************ Main TOpenapipfClient Class }

{ TOpenapipfClient}

constructor TOpenapipfClient.Create(const aClient: IJsonClient);
begin
  fClient := aClient;
  fClient.Options := [jcoParseTolerant, jcoHttpErrorRaise];
  fClient.UrlEncoder :=
    [ueEncodeNames, ueSkipVoidString, ueSkipVoidValue, ueStarNameIsCsv];
end;

procedure TOpenapipfClient.PostAuthJWTEndpoint();
begin
  fClient.Request('POST', '/api/v2/auth/jwt', [], [], []);
end;

procedure TOpenapipfClient.DeleteAuthKeyEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/auth/key', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PostAuthKeyEndpoint();
begin
  fClient.Request('POST', '/api/v2/auth/key', [], [], []);
end;

procedure TOpenapipfClient.DeleteAuthKeysEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/auth/keys', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetAuthKeysEndpoint(const Query: variant; Limit: integer;
  Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/auth/keys', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteDiagnosticsARPTableEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/diagnostics/arp_table', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetDiagnosticsARPTableEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/diagnostics/arp_table', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteDiagnosticsARPTableEntryEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/diagnostics/arp_table/entry', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetDiagnosticsARPTableEntryEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/diagnostics/arp_table/entry', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PostDiagnosticsCommandPromptEndpoint();
begin
  fClient.Request('POST', '/api/v2/diagnostics/command_prompt', [], [], []);
end;

procedure TOpenapipfClient.DeleteDiagnosticsConfigHistoryRevisionEndpoint(
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/diagnostics/config_history/revision', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetDiagnosticsConfigHistoryRevisionEndpoint(
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/diagnostics/config_history/revision', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.DeleteDiagnosticsConfigHistoryRevisionsEndpoint(
  const Query: variant; Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/diagnostics/config_history/revisions', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetDiagnosticsConfigHistoryRevisionsEndpoint(
  const Query: variant; Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray;
  const SortOrder: TEnumOpenapipf119; const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/diagnostics/config_history/revisions', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PostDiagnosticsHaltSystemEndpoint();
begin
  fClient.Request('POST', '/api/v2/diagnostics/halt_system', [], [], []);
end;

procedure TOpenapipfClient.PostDiagnosticsRebootEndpoint();
begin
  fClient.Request('POST', '/api/v2/diagnostics/reboot', [], [], []);
end;

procedure TOpenapipfClient.GetFirewallAdvancedSettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/firewall/advanced_settings', [], [], []);
end;

procedure TOpenapipfClient.PatchFirewallAdvancedSettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/advanced_settings', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallAliasEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/firewall/alias', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetFirewallAliasEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/alias', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallAliasEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/alias', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallAliasEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/alias', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallAliasesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/firewall/aliases', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetFirewallAliasesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/firewall/aliases', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutFirewallAliasesEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/firewall/aliases', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetFirewallApplyEndpoint();
begin
  fClient.Request('GET', '/api/v2/firewall/apply', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallApplyEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/apply', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallNATOneToOneMappingEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/firewall/nat/one_to_one/mapping', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetFirewallNATOneToOneMappingEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/nat/one_to_one/mapping', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallNATOneToOneMappingEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/nat/one_to_one/mapping', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallNATOneToOneMappingEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/nat/one_to_one/mapping', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallNATOneToOneMappingsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/firewall/nat/one_to_one/mappings', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetFirewallNATOneToOneMappingsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/firewall/nat/one_to_one/mappings', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutFirewallNATOneToOneMappingsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/firewall/nat/one_to_one/mappings', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteFirewallNATOutboundMappingEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/firewall/nat/outbound/mapping', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetFirewallNATOutboundMappingEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/nat/outbound/mapping', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallNATOutboundMappingEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/nat/outbound/mapping', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallNATOutboundMappingEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/nat/outbound/mapping', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallNATOutboundMappingsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/firewall/nat/outbound/mappings', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetFirewallNATOutboundMappingsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/firewall/nat/outbound/mappings', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutFirewallNATOutboundMappingsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/firewall/nat/outbound/mappings', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetFirewallNATOutboundModeEndpoint();
begin
  fClient.Request('GET', '/api/v2/firewall/nat/outbound/mode', [], [], []);
end;

procedure TOpenapipfClient.PatchFirewallNATOutboundModeEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/nat/outbound/mode', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallNATPortForwardEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/firewall/nat/port_forward', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetFirewallNATPortForwardEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/nat/port_forward', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallNATPortForwardEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/nat/port_forward', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallNATPortForwardEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/nat/port_forward', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallNATPortForwardsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/firewall/nat/port_forwards', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetFirewallNATPortForwardsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/firewall/nat/port_forwards', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutFirewallNATPortForwardsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/firewall/nat/port_forwards', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteFirewallRuleEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/firewall/rule', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetFirewallRuleEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/rule', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallRuleEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/rule', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallRuleEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/rule', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallRulesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/firewall/rules', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetFirewallRulesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/firewall/rules', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutFirewallRulesEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/firewall/rules', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteFirewallScheduleEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/firewall/schedule', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetFirewallScheduleEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/schedule', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallScheduleEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/schedule', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallScheduleEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/schedule', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallScheduleTimeRangeEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/firewall/schedule/time_range', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetFirewallScheduleTimeRangeEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/schedule/time_range', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallScheduleTimeRangeEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/schedule/time_range', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallScheduleTimeRangeEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/schedule/time_range', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallSchedulesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/firewall/schedules', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetFirewallSchedulesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/firewall/schedules', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutFirewallSchedulesEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/firewall/schedules', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteFirewallStateEndpoint_deprecated(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/firewall/state', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetFirewallStateEndpoint_deprecated(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/state', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.DeleteFirewallStatesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/firewall/states', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetFirewallStatesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/firewall/states', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetFirewallStatesSizeEndpoint();
begin
  fClient.Request('GET', '/api/v2/firewall/states/size', [], [], []);
end;

procedure TOpenapipfClient.PatchFirewallStatesSizeEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/states/size', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallTrafficShaperEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/firewall/traffic_shaper', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetFirewallTrafficShaperEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/traffic_shaper', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallTrafficShaperEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/traffic_shaper', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallTrafficShaperEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/traffic_shaper', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallTrafficShaperLimiterEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/firewall/traffic_shaper/limiter', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetFirewallTrafficShaperLimiterEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/traffic_shaper/limiter', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallTrafficShaperLimiterEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/traffic_shaper/limiter', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallTrafficShaperLimiterEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/traffic_shaper/limiter', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallTrafficShaperLimiterBandwidthEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/firewall/traffic_shaper/limiter/bandwidth', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetFirewallTrafficShaperLimiterBandwidthEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/traffic_shaper/limiter/bandwidth', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallTrafficShaperLimiterBandwidthEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/traffic_shaper/limiter/bandwidth', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallTrafficShaperLimiterBandwidthEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/traffic_shaper/limiter/bandwidth', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallTrafficShaperLimiterQueueEndpoint(
  const ParentId: variant; const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/firewall/traffic_shaper/limiter/queue', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetFirewallTrafficShaperLimiterQueueEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/traffic_shaper/limiter/queue', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallTrafficShaperLimiterQueueEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/traffic_shaper/limiter/queue', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallTrafficShaperLimiterQueueEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/traffic_shaper/limiter/queue', [], [], []);
end;

procedure TOpenapipfClient.GetFirewallTrafficShaperLimitersEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/firewall/traffic_shaper/limiters', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutFirewallTrafficShaperLimitersEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/firewall/traffic_shaper/limiters', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteFirewallTrafficShaperQueueEndpoint(const ParentId: variant;
  const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/firewall/traffic_shaper/queue', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetFirewallTrafficShaperQueueEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/traffic_shaper/queue', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallTrafficShaperQueueEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/traffic_shaper/queue', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallTrafficShaperQueueEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/traffic_shaper/queue', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallTrafficShapersEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/firewall/traffic_shapers', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetFirewallTrafficShapersEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/firewall/traffic_shapers', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutFirewallTrafficShapersEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/firewall/traffic_shapers', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteFirewallVirtualIPEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/firewall/virtual_ip', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetFirewallVirtualIPEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/firewall/virtual_ip', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchFirewallVirtualIPEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/firewall/virtual_ip', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallVirtualIPEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/virtual_ip', [], [], []);
end;

procedure TOpenapipfClient.GetFirewallVirtualIPApplyEndpoint();
begin
  fClient.Request('GET', '/api/v2/firewall/virtual_ip/apply', [], [], []);
end;

procedure TOpenapipfClient.PostFirewallVirtualIPApplyEndpoint();
begin
  fClient.Request('POST', '/api/v2/firewall/virtual_ip/apply', [], [], []);
end;

procedure TOpenapipfClient.DeleteFirewallVirtualIPsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/firewall/virtual_ips', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetFirewallVirtualIPsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/firewall/virtual_ips', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PostGraphQLEndpoint();
begin
  fClient.Request('POST', '/api/v2/graphql', [], [], []);
end;

procedure TOpenapipfClient.DeleteNetworkInterfaceEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/interface', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetNetworkInterfaceEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/interface', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchNetworkInterfaceEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/interface', [], [], []);
end;

procedure TOpenapipfClient.PostNetworkInterfaceEndpoint();
begin
  fClient.Request('POST', '/api/v2/interface', [], [], []);
end;

procedure TOpenapipfClient.GetInterfaceApplyEndpoint();
begin
  fClient.Request('GET', '/api/v2/interface/apply', [], [], []);
end;

procedure TOpenapipfClient.PostInterfaceApplyEndpoint();
begin
  fClient.Request('POST', '/api/v2/interface/apply', [], [], []);
end;

procedure TOpenapipfClient.GetInterfaceAvailableInterfacesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/interface/available_interfaces', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteInterfaceBridgeEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/interface/bridge', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetInterfaceBridgeEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/interface/bridge', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchInterfaceBridgeEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/interface/bridge', [], [], []);
end;

procedure TOpenapipfClient.PostInterfaceBridgeEndpoint();
begin
  fClient.Request('POST', '/api/v2/interface/bridge', [], [], []);
end;

procedure TOpenapipfClient.GetInterfaceBridgesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/interface/bridges', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteInterfaceGREEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/interface/gre', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetInterfaceGREEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/interface/gre', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchInterfaceGREEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/interface/gre', [], [], []);
end;

procedure TOpenapipfClient.PostInterfaceGREEndpoint();
begin
  fClient.Request('POST', '/api/v2/interface/gre', [], [], []);
end;

procedure TOpenapipfClient.DeleteInterfaceGREsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/interface/gres', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetInterfaceGREsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/interface/gres', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteInterfaceGroupEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/interface/group', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetInterfaceGroupEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/interface/group', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchInterfaceGroupEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/interface/group', [], [], []);
end;

procedure TOpenapipfClient.PostInterfaceGroupEndpoint();
begin
  fClient.Request('POST', '/api/v2/interface/group', [], [], []);
end;

procedure TOpenapipfClient.DeleteInterfaceGroupsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/interface/groups', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetInterfaceGroupsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/interface/groups', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutInterfaceGroupsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/interface/groups', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteInterfaceLAGGEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/interface/lagg', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetInterfaceLAGGEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/interface/lagg', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchInterfaceLAGGEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/interface/lagg', [], [], []);
end;

procedure TOpenapipfClient.PostInterfaceLAGGEndpoint();
begin
  fClient.Request('POST', '/api/v2/interface/lagg', [], [], []);
end;

procedure TOpenapipfClient.DeleteInterfaceLAGGsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/interface/laggs', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetInterfaceLAGGsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/interface/laggs', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteInterfaceVLANEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/interface/vlan', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetInterfaceVLANEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/interface/vlan', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchInterfaceVLANEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/interface/vlan', [], [], []);
end;

procedure TOpenapipfClient.PostInterfaceVLANEndpoint();
begin
  fClient.Request('POST', '/api/v2/interface/vlan', [], [], []);
end;

procedure TOpenapipfClient.DeleteInterfaceVLANsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/interface/vlans', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetInterfaceVLANsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/interface/vlans', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteNetworkInterfacesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/interfaces', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetNetworkInterfacesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/interfaces', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetRoutingApplyEndpoint();
begin
  fClient.Request('GET', '/api/v2/routing/apply', [], [], []);
end;

procedure TOpenapipfClient.PostRoutingApplyEndpoint();
begin
  fClient.Request('POST', '/api/v2/routing/apply', [], [], []);
end;

procedure TOpenapipfClient.DeleteRoutingGatewayEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/routing/gateway', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetRoutingGatewayEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/routing/gateway', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchRoutingGatewayEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/routing/gateway', [], [], []);
end;

procedure TOpenapipfClient.PostRoutingGatewayEndpoint();
begin
  fClient.Request('POST', '/api/v2/routing/gateway', [], [], []);
end;

procedure TOpenapipfClient.GetRoutingGatewayDefaultEndpoint();
begin
  fClient.Request('GET', '/api/v2/routing/gateway/default', [], [], []);
end;

procedure TOpenapipfClient.PatchRoutingGatewayDefaultEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/routing/gateway/default', [], [], []);
end;

procedure TOpenapipfClient.DeleteRoutingGatewayGroupEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/routing/gateway/group', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetRoutingGatewayGroupEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/routing/gateway/group', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchRoutingGatewayGroupEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/routing/gateway/group', [], [], []);
end;

procedure TOpenapipfClient.PostRoutingGatewayGroupEndpoint();
begin
  fClient.Request('POST', '/api/v2/routing/gateway/group', [], [], []);
end;

procedure TOpenapipfClient.DeleteRoutingGatewayGroupPriorityEndpoint(const ParentId: variant;
  const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/routing/gateway/group/priority', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetRoutingGatewayGroupPriorityEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/routing/gateway/group/priority', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchRoutingGatewayGroupPriorityEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/routing/gateway/group/priority', [], [], []);
end;

procedure TOpenapipfClient.PostRoutingGatewayGroupPriorityEndpoint();
begin
  fClient.Request('POST', '/api/v2/routing/gateway/group/priority', [], [], []);
end;

procedure TOpenapipfClient.DeleteRoutingGatewayGroupsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/routing/gateway/groups', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetRoutingGatewayGroupsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/routing/gateway/groups', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteRoutingGatewaysEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/routing/gateways', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetRoutingGatewaysEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/routing/gateways', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteRoutingStaticRouteEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/routing/static_route', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetRoutingStaticRouteEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/routing/static_route', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchRoutingStaticRouteEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/routing/static_route', [], [], []);
end;

procedure TOpenapipfClient.PostRoutingStaticRouteEndpoint();
begin
  fClient.Request('POST', '/api/v2/routing/static_route', [], [], []);
end;

procedure TOpenapipfClient.DeleteRoutingStaticRoutesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/routing/static_routes', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetRoutingStaticRoutesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/routing/static_routes', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteServicesACMEAccountKeyEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/acme/account_key', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesACMEAccountKeyEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/acme/account_key', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesACMEAccountKeyEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/acme/account_key', [], [], []);
end;

procedure TOpenapipfClient.PostServicesACMEAccountKeyEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/acme/account_key', [], [], []);
end;

procedure TOpenapipfClient.PostServicesACMEAccountKeyRegisterEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/acme/account_key/register', [], [], []);
end;

procedure TOpenapipfClient.GetServicesACMEAccountKeyRegistrationsEndpoint(
  const Query: variant; Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray;
  const SortOrder: TEnumOpenapipf119; const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/acme/account_key/registrations', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteServicesACMEAccountKeysEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/acme/account_keys', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesACMEAccountKeysEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/acme/account_keys', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesACMEAccountKeysEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/acme/account_keys', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteServicesACMECertificateEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/acme/certificate', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesACMECertificateEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/acme/certificate', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesACMECertificateEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/acme/certificate', [], [], []);
end;

procedure TOpenapipfClient.PostServicesACMECertificateEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/acme/certificate', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesACMECertificateActionEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/acme/certificate/action', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesACMECertificateActionEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/acme/certificate/action', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesACMECertificateActionEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/acme/certificate/action', [], [], []);
end;

procedure TOpenapipfClient.PostServicesACMECertificateActionEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/acme/certificate/action', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesACMECertificateDomainEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/acme/certificate/domain', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesACMECertificateDomainEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/acme/certificate/domain', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesACMECertificateDomainEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/acme/certificate/domain', [], [], []);
end;

procedure TOpenapipfClient.PostServicesACMECertificateDomainEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/acme/certificate/domain', [], [], []);
end;

procedure TOpenapipfClient.GetServicesACMECertificateIssuancesEndpoint(
  const Query: variant; Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray;
  const SortOrder: TEnumOpenapipf119; const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/acme/certificate/issuances', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PostServicesACMECertificateIssueEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/acme/certificate/issue', [], [], []);
end;

procedure TOpenapipfClient.PostServicesACMECertificateRenewEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/acme/certificate/renew', [], [], []);
end;

procedure TOpenapipfClient.GetServicesACMECertificateRenewalsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/acme/certificate/renewals', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteServicesACMECertificatesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/acme/certificates', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesACMECertificatesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/acme/certificates', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesACMECertificatesEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/acme/certificates', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetServicesACMESettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/acme/settings', [], [], []);
end;

procedure TOpenapipfClient.PatchServicesACMESettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/acme/settings', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesBINDAccessListEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/bind/access_list', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesBINDAccessListEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/bind/access_list', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesBINDAccessListEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/bind/access_list', [], [], []);
end;

procedure TOpenapipfClient.PostServicesBINDAccessListEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/bind/access_list', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesBINDAccessListEntryEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/bind/access_list/entry', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesBINDAccessListEntryEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/bind/access_list/entry', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesBINDAccessListEntryEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/bind/access_list/entry', [], [], []);
end;

procedure TOpenapipfClient.PostServicesBINDAccessListEntryEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/bind/access_list/entry', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesBINDAccessListsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/bind/access_lists', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesBINDAccessListsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/bind/access_lists', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesBINDAccessListsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/bind/access_lists', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetServicesBINDSettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/bind/settings', [], [], []);
end;

procedure TOpenapipfClient.PatchServicesBINDSettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/bind/settings', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesBINDSyncRemoteHostEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/bind/sync/remote_host', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesBINDSyncRemoteHostEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/bind/sync/remote_host', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesBINDSyncRemoteHostEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/bind/sync/remote_host', [], [], []);
end;

procedure TOpenapipfClient.PostServicesBINDSyncRemoteHostEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/bind/sync/remote_host', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesBINDSyncRemoteHostsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/bind/sync/remote_hosts', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesBINDSyncRemoteHostsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/bind/sync/remote_hosts', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesBINDSyncRemoteHostsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/bind/sync/remote_hosts', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetServicesBINDSyncSettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/bind/sync/settings', [], [], []);
end;

procedure TOpenapipfClient.PatchServicesBINDSyncSettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/bind/sync/settings', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesBINDViewEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/bind/view', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesBINDViewEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/bind/view', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesBINDViewEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/bind/view', [], [], []);
end;

procedure TOpenapipfClient.PostServicesBINDViewEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/bind/view', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesBINDViewsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/bind/views', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesBINDViewsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/bind/views', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesBINDViewsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/bind/views', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteServicesBINDZoneEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/bind/zone', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesBINDZoneEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/bind/zone', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesBINDZoneEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/bind/zone', [], [], []);
end;

procedure TOpenapipfClient.PostServicesBINDZoneEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/bind/zone', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesBINDZoneRecordEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/bind/zone/record', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesBINDZoneRecordEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/bind/zone/record', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesBINDZoneRecordEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/bind/zone/record', [], [], []);
end;

procedure TOpenapipfClient.PostServicesBINDZoneRecordEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/bind/zone/record', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesBINDZonesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/bind/zones', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesBINDZonesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/bind/zones', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesBINDZonesEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/bind/zones', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteServicesCronJobEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/cron/job', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesCronJobEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/cron/job', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesCronJobEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/cron/job', [], [], []);
end;

procedure TOpenapipfClient.PostServicesCronJobEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/cron/job', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesCronJobsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/cron/jobs', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesCronJobsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/cron/jobs', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesCronJobsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/cron/jobs', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetServicesDHCPServerEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dhcp_server', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDHCPServerEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dhcp_server', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDHCPServerAddressPoolEndpoint(
  const ParentId: variant; const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/services/dhcp_server/address_pool', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetServicesDHCPServerAddressPoolEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dhcp_server/address_pool', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDHCPServerAddressPoolEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dhcp_server/address_pool', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDHCPServerAddressPoolEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dhcp_server/address_pool', [], [], []);
end;

procedure TOpenapipfClient.GetServicesDHCPServerApplyEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/dhcp_server/apply', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDHCPServerApplyEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dhcp_server/apply', [], [], []);
end;

procedure TOpenapipfClient.PatchServicesDHCPServerBackendEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dhcp_server/backend', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDHCPServerCustomOptionEndpoint(
  const ParentId: variant; const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/services/dhcp_server/custom_option', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetServicesDHCPServerCustomOptionEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dhcp_server/custom_option', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDHCPServerCustomOptionEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dhcp_server/custom_option', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDHCPServerCustomOptionEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dhcp_server/custom_option', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDHCPServerStaticMappingEndpoint(
  const ParentId: variant; const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/services/dhcp_server/static_mapping', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetServicesDHCPServerStaticMappingEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dhcp_server/static_mapping', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDHCPServerStaticMappingEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dhcp_server/static_mapping', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDHCPServerStaticMappingEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dhcp_server/static_mapping', [], [], []);
end;

procedure TOpenapipfClient.GetServicesDHCPServersEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/dhcp_servers', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesDHCPServersEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/dhcp_servers', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetServicesDNSForwarderApplyEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/dns_forwarder/apply', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDNSForwarderApplyEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dns_forwarder/apply', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDNSForwarderHostOverrideEndpoint(
  const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_forwarder/host_override', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetServicesDNSForwarderHostOverrideEndpoint(
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dns_forwarder/host_override', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDNSForwarderHostOverrideEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dns_forwarder/host_override', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDNSForwarderHostOverrideEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dns_forwarder/host_override', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDNSForwarderHostOverrideAliasEndpoint(
  const ParentId: variant; const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_forwarder/host_override/alias', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetServicesDNSForwarderHostOverrideAliasEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dns_forwarder/host_override/alias', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDNSForwarderHostOverrideAliasEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dns_forwarder/host_override/alias', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDNSForwarderHostOverrideAliasEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dns_forwarder/host_override/alias', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDNSForwarderHostOverridesEndpoint(
  const Query: variant; Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_forwarder/host_overrides', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesDNSForwarderHostOverridesEndpoint(
  const Query: variant; Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray;
  const SortOrder: TEnumOpenapipf119; const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/dns_forwarder/host_overrides', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesDNSForwarderHostOverridesEndpoint(
  const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/dns_forwarder/host_overrides', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteServicesDNSResolverAccessListEndpoint(
  const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_resolver/access_list', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetServicesDNSResolverAccessListEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dns_resolver/access_list', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDNSResolverAccessListEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dns_resolver/access_list', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDNSResolverAccessListEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dns_resolver/access_list', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDNSResolverAccessListNetworkEndpoint(
  const ParentId: variant; const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_resolver/access_list/network', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetServicesDNSResolverAccessListNetworkEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dns_resolver/access_list/network', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDNSResolverAccessListNetworkEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dns_resolver/access_list/network', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDNSResolverAccessListNetworkEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dns_resolver/access_list/network', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDNSResolverAccessListsEndpoint(
  const Query: variant; Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_resolver/access_lists', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesDNSResolverAccessListsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/dns_resolver/access_lists', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesDNSResolverAccessListsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/dns_resolver/access_lists', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetServicesDNSResolverApplyEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/dns_resolver/apply', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDNSResolverApplyEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dns_resolver/apply', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDNSResolverDomainOverrideEndpoint(
  const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_resolver/domain_override', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetServicesDNSResolverDomainOverrideEndpoint(
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dns_resolver/domain_override', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDNSResolverDomainOverrideEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dns_resolver/domain_override', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDNSResolverDomainOverrideEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dns_resolver/domain_override', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDNSResolverDomainOverridesEndpoint(
  const Query: variant; Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_resolver/domain_overrides', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesDNSResolverDomainOverridesEndpoint(
  const Query: variant; Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray;
  const SortOrder: TEnumOpenapipf119; const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/dns_resolver/domain_overrides', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesDNSResolverDomainOverridesEndpoint(
  const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/dns_resolver/domain_overrides', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteServicesDNSResolverHostOverrideEndpoint(
  const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_resolver/host_override', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetServicesDNSResolverHostOverrideEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dns_resolver/host_override', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDNSResolverHostOverrideEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dns_resolver/host_override', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDNSResolverHostOverrideEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dns_resolver/host_override', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDNSResolverHostOverrideAliasEndpoint(
  const ParentId: variant; const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_resolver/host_override/alias', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetServicesDNSResolverHostOverrideAliasEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/dns_resolver/host_override/alias', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesDNSResolverHostOverrideAliasEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dns_resolver/host_override/alias', [], [], []);
end;

procedure TOpenapipfClient.PostServicesDNSResolverHostOverrideAliasEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/dns_resolver/host_override/alias', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesDNSResolverHostOverridesEndpoint(
  const Query: variant; Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/dns_resolver/host_overrides', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesDNSResolverHostOverridesEndpoint(
  const Query: variant; Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray;
  const SortOrder: TEnumOpenapipf119; const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/dns_resolver/host_overrides', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesDNSResolverHostOverridesEndpoint(
  const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/dns_resolver/host_overrides', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetServicesDNSResolverSettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/dns_resolver/settings', [], [], []);
end;

procedure TOpenapipfClient.PatchServicesDNSResolverSettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/dns_resolver/settings', [], [], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyApplyEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/haproxy/apply', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyApplyEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/apply', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyBackendEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/backend', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyBackendEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/backend', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyBackendEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/backend', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyBackendEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/backend', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyBackendACLEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/backend/acl', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyBackendACLEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/backend/acl', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyBackendACLEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/backend/acl', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyBackendACLEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/backend/acl', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyBackendActionEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/backend/action', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyBackendActionEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/backend/action', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyBackendActionEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/backend/action', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyBackendActionEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/backend/action', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyBackendErrorFileEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/backend/error_file', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyBackendErrorFileEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/backend/error_file', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyBackendErrorFileEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/backend/error_file', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyBackendErrorFileEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/backend/error_file', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyBackendServerEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/backend/server', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyBackendServerEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/backend/server', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyBackendServerEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/backend/server', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyBackendServerEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/backend/server', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyBackendsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/backends', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyBackendsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/backends', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesHAProxyBackendsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/haproxy/backends', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyFileEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/file', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyFileEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/file', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyFileEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/file', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyFileEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/file', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyFiles(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/files', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyFiles(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/files', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesHAProxyFiles(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/haproxy/files', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyFrontendEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/frontend', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyFrontendEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/frontend', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyFrontendEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/frontend', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyFrontendEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/frontend', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyFrontendACLEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/frontend/acl', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyFrontendACLEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/frontend/acl', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyFrontendACLEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/frontend/acl', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyFrontendACLEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/frontend/acl', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyFrontendActionEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/frontend/action', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyFrontendActionEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/frontend/action', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyFrontendActionEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/frontend/action', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyFrontendActionEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/frontend/action', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyFrontendAddressEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/frontend/address', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyFrontendAddressEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/frontend/address', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyFrontendAddressEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/frontend/address', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyFrontendAddressEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/frontend/address', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyFrontendErrorFileEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/frontend/error_file', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyFrontendErrorFileEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/frontend/error_file', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxyFrontendErrorFileEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/frontend/error_file', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxyFrontendErrorFileEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/frontend/error_file', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxyFrontendsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/frontends', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesHAProxyFrontendsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/frontends', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesHAProxyFrontendsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/haproxy/frontends', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetServicesHAProxySettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/haproxy/settings', [], [], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxySettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/settings', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxySettingsDNSResolverEndpoint(
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/settings/dns_resolver', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxySettingsDNSResolverEndpoint(
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/settings/dns_resolver', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxySettingsDNSResolverEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/settings/dns_resolver', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxySettingsDNSResolverEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/settings/dns_resolver', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesHAProxySettingsEmailMailerEndpoint(
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/haproxy/settings/email_mailer', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesHAProxySettingsEmailMailerEndpoint(
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/haproxy/settings/email_mailer', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesHAProxySettingsEmailMailerEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/haproxy/settings/email_mailer', [], [], []);
end;

procedure TOpenapipfClient.PostServicesHAProxySettingsEmailMailerEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/haproxy/settings/email_mailer', [], [], []);
end;

procedure TOpenapipfClient.GetServicesNTPSettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/ntp/settings', [], [], []);
end;

procedure TOpenapipfClient.PatchServicesNTPSettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/ntp/settings', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesNTPTimeServerEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/ntp/time_server', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesNTPTimeServerEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/ntp/time_server', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesNTPTimeServerEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/ntp/time_server', [], [], []);
end;

procedure TOpenapipfClient.PostServicesNTPTimeServerEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/ntp/time_server', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesNTPTimeServersEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/ntp/time_servers', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesNTPTimeServersEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/ntp/time_servers', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesNTPTimeServersEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/ntp/time_servers', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteServicesServiceWatchdogEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/services/service_watchdog', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetServicesServiceWatchdogEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/services/service_watchdog', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchServicesServiceWatchdogEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/service_watchdog', [], [], []);
end;

procedure TOpenapipfClient.PostServicesServiceWatchdogEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/service_watchdog', [], [], []);
end;

procedure TOpenapipfClient.DeleteServicesServiceWatchdogsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/services/service_watchdogs', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetServicesServiceWatchdogsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/services/service_watchdogs', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutServicesServiceWatchdogsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/services/service_watchdogs', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetServicesSSHEndpoint();
begin
  fClient.Request('GET', '/api/v2/services/ssh', [], [], []);
end;

procedure TOpenapipfClient.PatchServicesSSHEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/services/ssh', [], [], []);
end;

procedure TOpenapipfClient.PostServicesWakeOnLANSendEndpoint();
begin
  fClient.Request('POST', '/api/v2/services/wake_on_lan/send', [], [], []);
end;

procedure TOpenapipfClient.GetStatusCARPEndpoint();
begin
  fClient.Request('GET', '/api/v2/status/carp', [], [], []);
end;

procedure TOpenapipfClient.PatchStatusCARPEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/status/carp', [], [], []);
end;

procedure TOpenapipfClient.DeleteStatusDHCPServerLeasesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/status/dhcp_server/leases', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetStatusDHCPServerLeasesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/status/dhcp_server/leases', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetStatusGatewaysEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/status/gateways', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetStatusInterfacesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/status/interfaces', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetStatusIPsecChildSAEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/status/ipsec/child_sa', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetStatusIPsecSAsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/status/ipsec/sas', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetStatusLogsDHCPEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/status/logs/dhcp', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetStatusLogsFirewallEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/status/logs/firewall', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetStatusLogsSettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/status/logs/settings', [], [], []);
end;

procedure TOpenapipfClient.PatchStatusLogsSettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/status/logs/settings', [], [], []);
end;

procedure TOpenapipfClient.GetStatusLogsSystemEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/status/logs/system', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetStatusOpenVPNClientsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/status/openvpn/clients', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteStatusOpenVPNServerConnectionEndpoint(
  const ParentId: variant; const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/status/openvpn/server/connection', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetStatusOpenVPNServerConnectionEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/status/openvpn/server/connection', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetStatusOpenVPNServerRouteEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/status/openvpn/server/route', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetStatusOpenVPNServersEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/status/openvpn/servers', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PostStatusServiceEndpoint();
begin
  fClient.Request('POST', '/api/v2/status/service', [], [], []);
end;

procedure TOpenapipfClient.GetStatusServicesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/status/services', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetStatusSystemEndpoint();
begin
  fClient.Request('GET', '/api/v2/status/system', [], [], []);
end;

procedure TOpenapipfClient.DeleteSystemCertificateEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/system/certificate', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetSystemCertificateEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/system/certificate', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchSystemCertificateEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/certificate', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCertificateEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/certificate', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCertificateGenerateEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/certificate/generate', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCertificatePKCS12ExportEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/certificate/pkcs12/export', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCertificateRenewEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/certificate/renew', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCertificateSigningRequestEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/certificate/signing_request', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCertificateSigningRequestSignEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/certificate/signing_request/sign', [], [], []);
end;

procedure TOpenapipfClient.DeleteSystemCertificateAuthoritiesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/system/certificate_authorities', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetSystemCertificateAuthoritiesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/system/certificate_authorities', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteSystemCertificateAuthorityEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/system/certificate_authority', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetSystemCertificateAuthorityEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/system/certificate_authority', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchSystemCertificateAuthorityEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/certificate_authority', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCertificateAuthorityEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/certificate_authority', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCertificateAuthorityGenerateEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/certificate_authority/generate', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCertificateAuthorityRenewEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/certificate_authority/renew', [], [], []);
end;

procedure TOpenapipfClient.DeleteSystemCertificatesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/system/certificates', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetSystemCertificatesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/system/certificates', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetSystemConsoleEndpoint();
begin
  fClient.Request('GET', '/api/v2/system/console', [], [], []);
end;

procedure TOpenapipfClient.PatchSystemConsoleEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/console', [], [], []);
end;

procedure TOpenapipfClient.DeleteSystemCRLEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/system/crl', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetSystemCRLEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/system/crl', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchSystemCRLEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/crl', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCRLEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/crl', [], [], []);
end;

procedure TOpenapipfClient.DeleteSystemCRLRevokedCertificateEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/system/crl/revoked_certificate', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetSystemCRLRevokedCertificateEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/system/crl/revoked_certificate', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchSystemCRLRevokedCertificateEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/crl/revoked_certificate', [], [], []);
end;

procedure TOpenapipfClient.PostSystemCRLRevokedCertificateEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/crl/revoked_certificate', [], [], []);
end;

procedure TOpenapipfClient.DeleteSystemCRLsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/system/crls', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetSystemCRLsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/system/crls', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetSystemDNSEndpoint();
begin
  fClient.Request('GET', '/api/v2/system/dns', [], [], []);
end;

procedure TOpenapipfClient.PatchSystemDNSEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/dns', [], [], []);
end;

procedure TOpenapipfClient.GetSystemHostnameEndpoint();
begin
  fClient.Request('GET', '/api/v2/system/hostname', [], [], []);
end;

procedure TOpenapipfClient.PatchSystemHostnameEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/hostname', [], [], []);
end;

procedure TOpenapipfClient.GetSystemNotificationsEmailSettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/system/notifications/email_settings', [], [], []);
end;

procedure TOpenapipfClient.PatchSystemNotificationsEmailSettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/notifications/email_settings', [], [], []);
end;

procedure TOpenapipfClient.DeleteSystemPackageEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/system/package', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetSystemPackageEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/system/package', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PostSystemPackageEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/package', [], [], []);
end;

procedure TOpenapipfClient.GetSystemPackageAvailableEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/system/package/available', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteSystemPackagesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/system/packages', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetSystemPackagesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/system/packages', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteSystemRESTAPIAccessListEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/system/restapi/access_list', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetSystemRESTAPIAccessListEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/system/restapi/access_list', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutSystemRESTAPIAccessListEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/system/restapi/access_list', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteSystemRESTAPIAccessListEntryEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/system/restapi/access_list/entry', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetSystemRESTAPIAccessListEntryEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/system/restapi/access_list/entry', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchSystemRESTAPIAccessListEntryEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/restapi/access_list/entry', [], [], []);
end;

procedure TOpenapipfClient.PostSystemRESTAPIAccessListEntryEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/restapi/access_list/entry', [], [], []);
end;

procedure TOpenapipfClient.GetSystemRESTAPISettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/system/restapi/settings', [], [], []);
end;

procedure TOpenapipfClient.PatchSystemRESTAPISettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/restapi/settings', [], [], []);
end;

procedure TOpenapipfClient.PostSystemRESTAPISettingsSyncEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/restapi/settings/sync', [], [], []);
end;

procedure TOpenapipfClient.GetSystemRESTAPIVersionEndpoint();
begin
  fClient.Request('GET', '/api/v2/system/restapi/version', [], [], []);
end;

procedure TOpenapipfClient.PatchSystemRESTAPIVersionEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/restapi/version', [], [], []);
end;

procedure TOpenapipfClient.DeleteSystemTunableEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/system/tunable', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetSystemTunableEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/system/tunable', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchSystemTunableEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/tunable', [], [], []);
end;

procedure TOpenapipfClient.PostSystemTunableEndpoint();
begin
  fClient.Request('POST', '/api/v2/system/tunable', [], [], []);
end;

procedure TOpenapipfClient.DeleteSystemTunablesEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/system/tunables', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetSystemTunablesEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/system/tunables', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutSystemTunablesEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/system/tunables', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetSystemVersionEndpoint();
begin
  fClient.Request('GET', '/api/v2/system/version', [], [], []);
end;

procedure TOpenapipfClient.GetSystemWebGUISettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/system/webgui/settings', [], [], []);
end;

procedure TOpenapipfClient.PatchSystemWebGUISettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/system/webgui/settings', [], [], []);
end;

procedure TOpenapipfClient.DeleteUserEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/user', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetUserEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/user', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchUserEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/user', [], [], []);
end;

procedure TOpenapipfClient.PostUserEndpoint();
begin
  fClient.Request('POST', '/api/v2/user', [], [], []);
end;

procedure TOpenapipfClient.DeleteUserAuthServerEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/user/auth_server', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetUserAuthServerEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/user/auth_server', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchUserAuthServerEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/user/auth_server', [], [], []);
end;

procedure TOpenapipfClient.PostUserAuthServerEndpoint();
begin
  fClient.Request('POST', '/api/v2/user/auth_server', [], [], []);
end;

procedure TOpenapipfClient.DeleteUserAuthServersEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/user/auth_servers', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetUserAuthServersEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/user/auth_servers', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutUserAuthServersEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/user/auth_servers', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteUserGroupEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/user/group', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetUserGroupEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/user/group', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchUserGroupEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/user/group', [], [], []);
end;

procedure TOpenapipfClient.PostUserGroupEndpoint();
begin
  fClient.Request('POST', '/api/v2/user/group', [], [], []);
end;

procedure TOpenapipfClient.DeleteUserGroupsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/user/groups', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetUserGroupsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/user/groups', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutUserGroupsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/user/groups', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteUsersEndpoint(const Query: variant; Limit: integer;
  Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/users', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetUsersEndpoint(const Query: variant; Limit: integer;
  Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/users', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetVPNIPsecApplyEndpoint();
begin
  fClient.Request('GET', '/api/v2/vpn/ipsec/apply', [], [], []);
end;

procedure TOpenapipfClient.PostVPNIPsecApplyEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/ipsec/apply', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNIPsecPhase1Endpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/vpn/ipsec/phase1', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetVPNIPsecPhase1Endpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/ipsec/phase1', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNIPsecPhase1Endpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/ipsec/phase1', [], [], []);
end;

procedure TOpenapipfClient.PostVPNIPsecPhase1Endpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/ipsec/phase1', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNIPsecPhase1EncryptionEndpoint(const ParentId: variant;
  const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/vpn/ipsec/phase1/encryption', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetVPNIPsecPhase1EncryptionEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/ipsec/phase1/encryption', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNIPsecPhase1EncryptionEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/ipsec/phase1/encryption', [], [], []);
end;

procedure TOpenapipfClient.PostVPNIPsecPhase1EncryptionEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/ipsec/phase1/encryption', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNIPsecPhase1sEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/vpn/ipsec/phase1s', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetVPNIPsecPhase1sEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/vpn/ipsec/phase1s', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutVPNIPsecPhase1sEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/vpn/ipsec/phase1s', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteVPNIPsecPhase2Endpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/vpn/ipsec/phase2', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetVPNIPsecPhase2Endpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/ipsec/phase2', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNIPsecPhase2Endpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/ipsec/phase2', [], [], []);
end;

procedure TOpenapipfClient.PostVPNIPsecPhase2Endpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/ipsec/phase2', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNIPsecPhase2EncryptionEndpoint(const ParentId: variant;
  const Id: variant; Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/vpn/ipsec/phase2/encryption', [], [
    'parent_id', ParentId,
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetVPNIPsecPhase2EncryptionEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/ipsec/phase2/encryption', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNIPsecPhase2EncryptionEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/ipsec/phase2/encryption', [], [], []);
end;

procedure TOpenapipfClient.PostVPNIPsecPhase2EncryptionEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/ipsec/phase2/encryption', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNIPsecPhase2sEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/vpn/ipsec/phase2s', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetVPNIPsecPhase2sEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/vpn/ipsec/phase2s', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutVPNIPsecPhase2sEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/vpn/ipsec/phase2s', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.DeleteVPNOpenVPNClientEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/vpn/openvpn/client', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetVPNOpenVPNClientEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/openvpn/client', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNOpenVPNClientEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/openvpn/client', [], [], []);
end;

procedure TOpenapipfClient.PostVPNOpenVPNClientEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/openvpn/client', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNOpenVPNClientsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/vpn/openvpn/clients', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetVPNOpenVPNClientsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/vpn/openvpn/clients', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteVPNOpenVPNCSOEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/vpn/openvpn/cso', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetVPNOpenVPNCSOEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/openvpn/cso', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNOpenVPNCSOEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/openvpn/cso', [], [], []);
end;

procedure TOpenapipfClient.PostVPNOpenVPNCSOEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/openvpn/cso', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNOpenVPNCSOsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/vpn/openvpn/csos', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetVPNOpenVPNCSOsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/vpn/openvpn/csos', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.DeleteVPNOpenVPNServerEndpoint(const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/vpn/openvpn/server', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.GetVPNOpenVPNServerEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/openvpn/server', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNOpenVPNServerEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/openvpn/server', [], [], []);
end;

procedure TOpenapipfClient.PostVPNOpenVPNServerEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/openvpn/server', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNOpenVPNServersEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/vpn/openvpn/servers', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetVPNOpenVPNServersEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/vpn/openvpn/servers', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.GetVPNWireGuardApplyEndpoint();
begin
  fClient.Request('GET', '/api/v2/vpn/wireguard/apply', [], [], []);
end;

procedure TOpenapipfClient.PostVPNWireGuardApplyEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/wireguard/apply', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNWireGuardPeerEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/vpn/wireguard/peer', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetVPNWireGuardPeerEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/wireguard/peer', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNWireGuardPeerEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/wireguard/peer', [], [], []);
end;

procedure TOpenapipfClient.PostVPNWireGuardPeerEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/wireguard/peer', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNWireGuardPeerAllowedIPEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/vpn/wireguard/peer/allowed_ip', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetVPNWireGuardPeerAllowedIPEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/wireguard/peer/allowed_ip', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNWireGuardPeerAllowedIPEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/wireguard/peer/allowed_ip', [], [], []);
end;

procedure TOpenapipfClient.PostVPNWireGuardPeerAllowedIPEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/wireguard/peer/allowed_ip', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNWireGuardPeersEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/vpn/wireguard/peers', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetVPNWireGuardPeersEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/vpn/wireguard/peers', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutVPNWireGuardPeersEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/vpn/wireguard/peers', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;

procedure TOpenapipfClient.GetVPNWireGuardSettingsEndpoint();
begin
  fClient.Request('GET', '/api/v2/vpn/wireguard/settings', [], [], []);
end;

procedure TOpenapipfClient.PatchVPNWireGuardSettingsEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/wireguard/settings', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNWireGuardTunnelEndpoint(const Id: variant;
  Apply: boolean);
begin
  fClient.Request('DELETE', '/api/v2/vpn/wireguard/tunnel', [], [
    'id', Id,
    'apply', Apply], []);
end;

procedure TOpenapipfClient.GetVPNWireGuardTunnelEndpoint(const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/wireguard/tunnel', [], [
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNWireGuardTunnelEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/wireguard/tunnel', [], [], []);
end;

procedure TOpenapipfClient.PostVPNWireGuardTunnelEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/wireguard/tunnel', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNWireGuardTunnelAddressEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('DELETE', '/api/v2/vpn/wireguard/tunnel/address', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.GetVPNWireGuardTunnelAddressEndpoint(const ParentId: variant;
  const Id: variant);
begin
  fClient.Request('GET', '/api/v2/vpn/wireguard/tunnel/address', [], [
    'parent_id', ParentId,
    'id', Id], []);
end;

procedure TOpenapipfClient.PatchVPNWireGuardTunnelAddressEndpoint();
begin
  fClient.Request('PATCH', '/api/v2/vpn/wireguard/tunnel/address', [], [], []);
end;

procedure TOpenapipfClient.PostVPNWireGuardTunnelAddressEndpoint();
begin
  fClient.Request('POST', '/api/v2/vpn/wireguard/tunnel/address', [], [], []);
end;

procedure TOpenapipfClient.DeleteVPNWireGuardTunnelsEndpoint(const Query: variant;
  Limit: integer; Offset: integer);
begin
  fClient.Request('DELETE', '/api/v2/vpn/wireguard/tunnels', [], [
    'limit', Limit,
    'offset', Offset,
    'query', Query], []);
end;

procedure TOpenapipfClient.GetVPNWireGuardTunnelsEndpoint(const Query: variant;
  Limit: integer; Offset: integer; const SortBy: TRawUtf8DynArray; const SortOrder: TEnumOpenapipf119;
  const SortFlags: TEnumOpenapipf120);
begin
  fClient.Request('GET', '/api/v2/vpn/wireguard/tunnels', [], [
    'limit', Limit,
    'offset', Offset,
    '*sort_by', RawUtf8ArrayToCsv(SortBy),
    'sort_order', ENUMOPENAPIPF119_TXT[SortOrder],
    'sort_flags', ENUMOPENAPIPF120_TXT[SortFlags],
    'query', Query], []);
end;

procedure TOpenapipfClient.PutVPNWireGuardTunnelsEndpoint(const Payload: variant);
begin
  fClient.Request('PUT', '/api/v2/vpn/wireguard/tunnels', [], [], [],
    Payload, {dummy:}self, TypeInfo(variant), nil);
end;


{ ************ Custom RTTI/JSON initialization }

const
  // exact definition of the DTOs expected JSON serialization
  _TACMEAccountKey = 'accountkey:RawUtf8 acmeserver:RawUtf8 descr:RawUtf8 ' +
    'email:RawUtf8 name:RawUtf8';
  _TACMEAccountKeyRegister = 'name:RawUtf8 status:RawUtf8';
  _TACMECertificate = 'a_actionlist:variant a_domainlist:variant acmeaccount:RawUtf8 ' +
    'descr:RawUtf8 dnssleep:integer keylength:TEnumOpenapipf1 keypaste:RawUtf8 ' +
    'name:RawUtf8 oscpstaple:boolean preferredchain:RawUtf8 renewafter:integer ' +
    'status:TEnumOpenapipf2';
  _TACMECertificateAction = 'command:RawUtf8 method:TEnumOpenapipf3 status:TEnumOpenapipf2';
  _TACMECertificateDomain = 'ULTRA_PWD:RawUtf8 acmedns_password:RawUtf8 acmedns_subdomain:RawUtf8 ' +
    'acmedns_update_url:RawUtf8 acmedns_username:RawUtf8 acmeproxy_endpoint:RawUtf8 ' +
    'acmeproxy_password:RawUtf8 acmeproxy_username:RawUtf8 active24_token:RawUtf8 ' +
    'ad_api_key:RawUtf8 af_api_password:RawUtf8 af_api_username:RawUtf8 akamai_access_token:RawUtf8 ' +
    'akamai_client_secret:RawUtf8 akamai_client_token:RawUtf8 akamai_host:RawUtf8 ' +
    'ali_key:RawUtf8 ali_secret:RawUtf8 anx_token:RawUtf8 anydnschallengealias:RawUtf8 ' +
    'anydnschallengedomain:boolean arvan_token:RawUtf8 aurora_key:RawUtf8 aurora_secret:RawUtf8 ' +
    'autodns_context:RawUtf8 autodns_password:RawUtf8 autodns_user:RawUtf8 aws_access_key_id:RawUtf8 ' +
    'aws_dns_slowrate:RawUtf8 aws_secret_access_key:RawUtf8 azion_email:RawUtf8 ' +
    'azion_password:RawUtf8 azuredns_appid:RawUtf8 azuredns_clientsecret:RawUtf8 ' +
    'azuredns_subscriptionid:RawUtf8 azuredns_tenantid:RawUtf8 bookmyname_password:RawUtf8 ' +
    'bookmyname_username:RawUtf8 bunny_api_key:RawUtf8 cf_account_id:RawUtf8 ' +
    'cf_email:RawUtf8 cf_key:RawUtf8 cf_token:RawUtf8 cf_zone_id:RawUtf8 clouddns_client_id:RawUtf8 ' +
    'clouddns_email:RawUtf8 clouddns_password:RawUtf8 cloudns_auth_id:RawUtf8 ' +
    'cloudns_auth_password:RawUtf8 cloudns_sub_auth_id:RawUtf8 cn_password:RawUtf8 ' +
    'cn_user:RawUtf8 conoha_identityserviceapi:RawUtf8 conoha_password:RawUtf8 ' +
    'conoha_tenantid:RawUtf8 conoha_username:RawUtf8 constellix_key:RawUtf8 ' +
    'constellix_secret:RawUtf8 cpanel_apitoken:RawUtf8 cpanel_hostname:RawUtf8 ' +
    'cpanel_username:RawUtf8 curanet_authclientid:RawUtf8 curanet_authsecret:RawUtf8 ' +
    'cy_password:RawUtf8 cy_username:RawUtf8 da_api:RawUtf8 da_api_insecure:RawUtf8 ' +
    'dd_api_key:RawUtf8 dd_api_user:RawUtf8 ddnss_token:RawUtf8 dedyn_name:RawUtf8 ' +
    'dedyn_token:RawUtf8 default_infomaniak_api_url:RawUtf8 df_password:RawUtf8 ' +
    'df_user:RawUtf8 dh_api_key:RawUtf8 dnsexit_api_key:RawUtf8 dnsexit_auth_pass:RawUtf8 ' +
    'dnsexit_auth_user:RawUtf8 dnshome_subdomain:RawUtf8 dnshome_subdomainpassword:RawUtf8 ' +
    'dnsimple_oauth_token:RawUtf8 dnsservices_password:RawUtf8 dnsservices_username:RawUtf8 ' +
    'do_api_key:RawUtf8 do_letoken:RawUtf8 do_pid:RawUtf8 do_pw:RawUtf8 domeneshop_secret:RawUtf8 ' +
    'domeneshop_token:RawUtf8 dp_id:RawUtf8 dp_key:RawUtf8 dpi_id:RawUtf8 dpi_key:RawUtf8 ' +
    'duckdns_token:RawUtf8 dyn_customer:RawUtf8 dyn_password:RawUtf8 dyn_username:RawUtf8 ' +
    'dynu_clientid:RawUtf8 dynu_secret:RawUtf8 easydns_key:RawUtf8 easydns_token:RawUtf8 ' +
    'euserv_password:RawUtf8 euserv_username:RawUtf8 exoscale_api_key:RawUtf8 ' +
    'exoscale_secret_key:RawUtf8 fornex_api_key:RawUtf8 freedns_password:RawUtf8 ' +
    'freedns_user:RawUtf8 gandi_livedns_key:RawUtf8 gcore_key:RawUtf8 gd_key:RawUtf8 ' +
    'gd_secret:RawUtf8 geoscaling_password:RawUtf8 geoscaling_username:RawUtf8 ' +
    'googledomains_access_token:RawUtf8 googledomains_zone:RawUtf8 he_password:RawUtf8 ' +
    'he_username:RawUtf8 hetzner_token:RawUtf8 hexonet_login:RawUtf8 hexonet_password:RawUtf8 ' +
    'hostingde_apikey:RawUtf8 hostingde_endpoint:RawUtf8 huaweicloud_domainname:RawUtf8 ' +
    'huaweicloud_password:RawUtf8 huaweicloud_username:RawUtf8 infoblox_creds:RawUtf8 ' +
    'infoblox_server:RawUtf8 infoblox_view:RawUtf8 infomaniak_api_token:RawUtf8 ' +
    'infomaniak_ttl:RawUtf8 internetbs_api_key:RawUtf8 internetbs_api_password:RawUtf8 ' +
    'inwx_password:RawUtf8 inwx_shared_secret:RawUtf8 inwx_username:RawUtf8 ' +
    'ionos_prefix:RawUtf8 ionos_secret:RawUtf8 ipv64_token:RawUtf8 ispc_api:RawUtf8 ' +
    'ispc_api_insecure:RawUtf8 ispc_password:RawUtf8 ispc_user:RawUtf8 jd_access_key_id:RawUtf8 ' +
    'jd_access_key_secret:RawUtf8 jd_region:RawUtf8 joker_password:RawUtf8 joker_username:RawUtf8 ' +
    'kappernetdns_key:RawUtf8 kappernetdns_secret:RawUtf8 kas_authdata:RawUtf8 ' +
    'kas_authtype:RawUtf8 kas_login:RawUtf8 kinghost_password:RawUtf8 kinghost_username:RawUtf8 ' +
    'knot_key:RawUtf8 knot_server:RawUtf8 la_id:RawUtf8 la_key:RawUtf8 limacity_apikey:RawUtf8 ' +
    'linode_api_key:RawUtf8 linode_v4_api_key:RawUtf8 loopia_password:RawUtf8 ' +
    'loopia_user:RawUtf8 lsw_key:RawUtf8 lua_email:RawUtf8 lua_key:RawUtf8 mb_ak:RawUtf8 ' +
    'mb_as:RawUtf8 me_key:RawUtf8 me_secret:RawUtf8 method:RawUtf8 miab_password:RawUtf8 ' +
    'miab_server:RawUtf8 miab_username:RawUtf8 misaka_key:RawUtf8 mydnsjp_masterid:RawUtf8 ' +
    'mydnsjp_password:RawUtf8 name:RawUtf8 namecheap_api_key:RawUtf8 namecheap_username:RawUtf8 ' +
    'namecom_token:RawUtf8 namecom_username:RawUtf8 namesilo_key:RawUtf8 nanelo_token:RawUtf8 ' +
    'nc_apikey:RawUtf8 nc_apipw:RawUtf8 nc_cid:RawUtf8 nederhost_key:RawUtf8 ' +
    'neodigit_api_token:RawUtf8 netlify_access_token:RawUtf8 nic_clientid:RawUtf8 ' +
    'nic_clientsecret:RawUtf8 nic_password:RawUtf8 nic_username:RawUtf8 nm_sha256:RawUtf8 ' +
    'nm_user:RawUtf8 ns1_key:RawUtf8 nsupdate_key:RawUtf8 nsupdate_keyalgo:TEnumOpenapipf4 ' +
    'nsupdate_keyname:RawUtf8 nsupdate_server:RawUtf8 nsupdate_zone:RawUtf8 ' +
    'nw_api_endpoint:TEnumOpenapipf5 nw_api_token:RawUtf8 oci_cli_key:RawUtf8 ' +
    'oci_cli_region:RawUtf8 oci_cli_tenancy:RawUtf8 oci_cli_user:RawUtf8 one984hosting_password:RawUtf8 ' +
    'one984hosting_username:RawUtf8 onecom_password:RawUtf8 onecom_user:RawUtf8 ' +
    'online_api_key:RawUtf8 openprovider_passwordhash:RawUtf8 openprovider_user:RawUtf8 ' +
    'ovh_ak:RawUtf8 ovh_as:RawUtf8 ovh_ck:RawUtf8 ovh_end_point:TEnumOpenapipf6 ' +
    'pdd_token:RawUtf8 pdns_serverid:RawUtf8 pdns_token:RawUtf8 pdns_ttl:RawUtf8 ' +
    'pdns_url:RawUtf8 pleskxml_pass:RawUtf8 pleskxml_uri:RawUtf8 pleskxml_user:RawUtf8 ' +
    'pointhq_email:RawUtf8 pointhq_key:RawUtf8 porkbun_api_key:RawUtf8 porkbun_secret_api_key:RawUtf8 ' +
    'rackcorp_apisecret:RawUtf8 rackcorp_apiuuid:RawUtf8 rackspace_apikey:RawUtf8 ' +
    'rackspace_username:RawUtf8 rage4_token:RawUtf8 rage4_username:RawUtf8 rcode0_api_token:RawUtf8 ' +
    'rcode0_ttl:RawUtf8 rcode0_url:RawUtf8 regru_api_password:RawUtf8 regru_api_username:RawUtf8 ' +
    'scaleway_api_token:RawUtf8 schlundtech_password:RawUtf8 schlundtech_user:RawUtf8 ' +
    'selfhostdns_map:RawUtf8 selfhostdns_password:RawUtf8 selfhostdns_username:RawUtf8 ' +
    'servercow_api_password:RawUtf8 servercow_api_username:RawUtf8 simply_accountname:RawUtf8 ' +
    'simply_api:RawUtf8 simply_apikey:RawUtf8 sl_key:RawUtf8 standaloneipv6:boolean ' +
    'standaloneport:RawUtf8 standalonetlsport:RawUtf8 status:TEnumOpenapipf7 ' +
    'tele3_key:RawUtf8 tele3_secret:RawUtf8 tencent_secretid:RawUtf8 tencent_secretkey:RawUtf8 ' +
    'udr_pass:RawUtf8 udr_user:RawUtf8 ultra_usr:RawUtf8 uno_key:RawUtf8 uno_user:RawUtf8 ' +
    'variomedia_api_token:RawUtf8 veesp_password:RawUtf8 veesp_user:RawUtf8 ' +
    'vercel_token:RawUtf8 vscale_api_key:RawUtf8 vultr_api_key:RawUtf8 webrootfolder:RawUtf8 ' +
    'webrootftpfolder:RawUtf8 webrootftpftpserver:RawUtf8 webrootftppassword:RawUtf8 ' +
    'webrootftpusername:RawUtf8 west_key:RawUtf8 west_username:RawUtf8 world4you_password:RawUtf8 ' +
    'world4you_username:RawUtf8 ws_apikey:RawUtf8 ws_apisecret:RawUtf8 yc_folder_id:RawUtf8 ' +
    'yc_sa_id:RawUtf8 yc_sa_key_file_pem_b64:RawUtf8 yc_sa_key_id:RawUtf8 yc_zone_id:RawUtf8 ' +
    'zilore_key:RawUtf8 zm_key:RawUtf8 zone_key:RawUtf8 zone_username:RawUtf8';
  _TACMECertificateIssue = 'certificate:RawUtf8 last_updated:integer result_log:RawUtf8 ' +
    'status:RawUtf8';
  _TACMECertificateRenew = 'certificate:RawUtf8 last_updated:integer result_log:RawUtf8 ' +
    'status:RawUtf8';
  _TACMESettings = 'enable:boolean writecerts:boolean';
  _TARPTable = 'dnsresolve:RawUtf8 expires:RawUtf8 hostname:RawUtf8 interface:RawUtf8 ' +
    'ip_address:RawUtf8 mac_address:RawUtf8 permanent:boolean type:RawUtf8';
  _TAuthServer = 'host:RawUtf8 ldap_allow_unauthenticated:boolean ldap_attr_group:RawUtf8 ' +
    'ldap_attr_groupobj:RawUtf8 ldap_attr_member:RawUtf8 ldap_attr_user:RawUtf8 ' +
    'ldap_authcn:RawUtf8 ldap_basedn:RawUtf8 ldap_binddn:RawUtf8 ldap_bindpw:RawUtf8 ' +
    'ldap_caref:RawUtf8 ldap_extended_enabled:boolean ldap_extended_query:RawUtf8 ' +
    'ldap_nostrip_at:boolean ldap_pam_groupdn:RawUtf8 ldap_port:RawUtf8 ldap_protver:integer ' +
    'ldap_rfc2307:boolean ldap_rfc2307_userdn:boolean ldap_scope:TEnumOpenapipf8 ' +
    'ldap_timeout:integer ldap_urltype:TEnumOpenapipf9 ldap_utf8:boolean name:RawUtf8 ' +
    'radius_acct_port:RawUtf8 radius_auth_port:RawUtf8 radius_nasip_attribute:RawUtf8 ' +
    'radius_protocol:TEnumOpenapipf10 radius_secret:RawUtf8 radius_timeout:integer ' +
    'refid:RawUtf8 type:TEnumOpenapipf11';
  _TAuthenticationError = '_links:variant code:integer data:variant message:RawUtf8 ' +
    'response_id:RawUtf8 status:RawUtf8';
  _TAvailableInterface = 'dmesg:RawUtf8 if:RawUtf8 in_use_by:RawUtf8 mac:RawUtf8';
  _TAvailablePackage = 'deps:TRawUtf8DynArray descr:RawUtf8 installed:boolean ' +
    'name:RawUtf8 shortname:RawUtf8 version:RawUtf8';
  _TBINDAccessList = 'description:RawUtf8 entries:variant name:RawUtf8';
  _TBINDAccessListEntry = 'description:RawUtf8 value:RawUtf8';
  _TBINDSettings = 'bind_custom_options:RawUtf8 bind_dnssec_validation:TEnumOpenapipf12 ' +
    'bind_forwarder:boolean bind_forwarder_ips:TRawUtf8DynArray bind_global_settings:RawUtf8 ' +
    'bind_hide_version:boolean bind_ip_version:TEnumOpenapipf13 bind_logging:boolean ' +
    'bind_notify:boolean bind_ram_limit:RawUtf8 controlport:RawUtf8 enable_bind:boolean ' +
    'listenon:TRawUtf8DynArray listenport:RawUtf8 log_only:boolean log_options:TEnumOpenapipf14Set ' +
    'log_severity:TEnumOpenapipf15 rate_enabled:boolean rate_limit:integer';
  _TBINDSyncRemoteHost = 'ipaddress:RawUtf8 password:RawUtf8 syncdestinenable:boolean ' +
    'syncport:RawUtf8 syncprotocol:TEnumOpenapipf16 username:RawUtf8';
  _TBINDSyncSettings = 'masterip:RawUtf8 synconchanges:TEnumOpenapipf17 synctimeout:integer';
  _TBINDView = 'allow_recursion:TRawUtf8DynArray bind_custom_options:RawUtf8 ' +
    'descr:RawUtf8 match_clients:TRawUtf8DynArray name:RawUtf8 recursion:boolean';
  _TBINDZone = 'allowquery:TRawUtf8DynArray allowtransfer:TRawUtf8DynArray ' +
    'allowupdate:TRawUtf8DynArray backupkeys:boolean baseip:RawUtf8 custom:RawUtf8 ' +
    'customzonerecords:RawUtf8 description:RawUtf8 disabled:boolean dnssec:boolean ' +
    'enable_updatepolicy:boolean expire:integer forwarders:TRawUtf8DynArray ' +
    'mail:RawUtf8 minimum:integer name:RawUtf8 nameserver:RawUtf8 records:variant ' +
    'refresh:integer regdhcpstatic:boolean retry:integer reversev4:boolean reversev6:boolean ' +
    'rpz:boolean serial:integer slaveip:RawUtf8 ttl:integer type:TEnumOpenapipf18 ' +
    'updatepolicy:RawUtf8 view:TRawUtf8DynArray';
  _TBINDZoneRecord = 'name:RawUtf8 priority:integer rdata:RawUtf8 type:TEnumOpenapipf19';
  _TCARP = 'enable:boolean maintenance_mode:boolean';
  _TCertificate = 'caref:RawUtf8 crt:RawUtf8 csr:RawUtf8 descr:RawUtf8 prv:RawUtf8 ' +
    'refid:RawUtf8 type:TEnumOpenapipf20';
  _TCertificateAuthority = 'crt:RawUtf8 descr:RawUtf8 prv:RawUtf8 randomserial:boolean ' +
    'refid:RawUtf8 serial:integer trust:boolean';
  _TCertificateAuthorityGenerate = 'caref:RawUtf8 crt:RawUtf8 descr:RawUtf8 ' +
    'digest_alg:RawUtf8 dn_city:RawUtf8 dn_commonname:RawUtf8 dn_country:RawUtf8 ' +
    'dn_organization:RawUtf8 dn_organizationalunit:RawUtf8 dn_state:RawUtf8 ' +
    'ecname:RawUtf8 is_intermediate:boolean keylen:integer keytype:TEnumOpenapipf21 ' +
    'lifetime:integer prv:RawUtf8 randomserial:boolean refid:RawUtf8 serial:integer ' +
    'trust:boolean';
  _TCertificateAuthorityRenew = 'caref:RawUtf8 newserial:RawUtf8 oldserial:RawUtf8 ' +
    'reusekey:boolean reuseserial:boolean strictsecurity:boolean';
  _TCertificateGenerate = 'caref:RawUtf8 crt:RawUtf8 descr:RawUtf8 digest_alg:RawUtf8 ' +
    'dn_city:RawUtf8 dn_commonname:RawUtf8 dn_country:RawUtf8 dn_dns_sans:TRawUtf8DynArray ' +
    'dn_email_sans:TRawUtf8DynArray dn_ip_sans:TRawUtf8DynArray dn_organization:RawUtf8 ' +
    'dn_organizationalunit:RawUtf8 dn_state:RawUtf8 dn_uri_sans:TRawUtf8DynArray ' +
    'ecname:RawUtf8 keylen:integer keytype:TEnumOpenapipf21 lifetime:integer ' +
    'prv:RawUtf8 refid:RawUtf8 type:TEnumOpenapipf20';
  _TCertificatePKCS12Export = 'binary_data:RawUtf8 certref:RawUtf8 encryption:TEnumOpenapipf22 ' +
    'filename:RawUtf8 passphrase:RawUtf8';
  _TCertificateRenew = 'certref:RawUtf8 newserial:RawUtf8 oldserial:RawUtf8 ' +
    'reusekey:boolean reuseserial:boolean strictsecurity:boolean';
  _TCertificateRevocationList = 'caref:RawUtf8 cert:variant descr:RawUtf8 ' +
    'lifetime:integer method:TEnumOpenapipf23 refid:RawUtf8 serial:integer text:RawUtf8';
  _TCertificateRevocationListRevokedCertificate = 'caref:RawUtf8 certref:RawUtf8 ' +
    'crt:RawUtf8 descr:RawUtf8 prv:RawUtf8 reason:integer revoke_time:integer ' +
    'serial:RawUtf8 type:RawUtf8';
  _TCertificateSigningRequest = 'csr:RawUtf8 descr:RawUtf8 digest_alg:RawUtf8 ' +
    'dn_city:RawUtf8 dn_commonname:RawUtf8 dn_country:RawUtf8 dn_dns_sans:TRawUtf8DynArray ' +
    'dn_email_sans:TRawUtf8DynArray dn_ip_sans:TRawUtf8DynArray dn_organization:RawUtf8 ' +
    'dn_organizationalunit:RawUtf8 dn_state:RawUtf8 dn_uri_sans:TRawUtf8DynArray ' +
    'ecname:RawUtf8 keylen:integer keytype:TEnumOpenapipf21 lifetime:integer ' +
    'prv:RawUtf8 refid:RawUtf8 type:TEnumOpenapipf20';
  _TCertificateSigningRequestSign = 'caref:RawUtf8 crt:RawUtf8 csr:RawUtf8 ' +
    'descr:RawUtf8 digest_alg:RawUtf8 dn_dns_sans:TRawUtf8DynArray dn_email_sans:TRawUtf8DynArray ' +
    'dn_ip_sans:TRawUtf8DynArray dn_uri_sans:TRawUtf8DynArray lifetime:integer ' +
    'prv:RawUtf8 refid:RawUtf8 type:TEnumOpenapipf20';
  _TCommandPrompt = 'command:RawUtf8 output:RawUtf8 result_code:integer';
  _TConfigHistoryRevision = 'description:RawUtf8 filesize:integer time:integer ' +
    'version:RawUtf8';
  _TConflictError = '_links:variant code:integer data:variant message:RawUtf8 ' +
    'response_id:RawUtf8 status:RawUtf8';
  _TCronJob = 'command:RawUtf8 hour:RawUtf8 mday:RawUtf8 minute:RawUtf8 month:RawUtf8 ' +
    'wday:RawUtf8 who:RawUtf8';
  _TDHCPLog = 'text:RawUtf8';
  _TDHCPServer = 'defaultleasetime:integer denyunknown:TEnumOpenapipf24 dhcpleaseinlocaltime:boolean ' +
    'disablepingcheck:boolean dnsserver:TRawUtf8DynArray domain:RawUtf8 domainsearchlist:TRawUtf8DynArray ' +
    'enable:boolean failover_peerip:RawUtf8 gateway:RawUtf8 ignorebootp:boolean ' +
    'ignoreclientuids:boolean interface:RawUtf8 mac_allow:TRawUtf8DynArray mac_deny:TRawUtf8DynArray ' +
    'maxleasetime:integer nonak:boolean ntpserver:TRawUtf8DynArray numberoptions:variant ' +
    'pool:variant range_from:RawUtf8 range_to:RawUtf8 staticarp:boolean staticmap:variant ' +
    'statsgraph:boolean winsserver:TRawUtf8DynArray';
  _TDHCPServerAddressPool = 'defaultleasetime:integer denyunknown:TEnumOpenapipf24 ' +
    'dnsserver:TRawUtf8DynArray domain:RawUtf8 domainsearchlist:TRawUtf8DynArray ' +
    'gateway:RawUtf8 ignorebootp:boolean ignoreclientuids:boolean mac_allow:TRawUtf8DynArray ' +
    'mac_deny:TRawUtf8DynArray maxleasetime:integer ntpserver:TRawUtf8DynArray ' +
    'range_from:RawUtf8 range_to:RawUtf8 winsserver:TRawUtf8DynArray';
  _TDHCPServerApply = 'applied:boolean';
  _TDHCPServerBackend = 'dhcpbackend:TEnumOpenapipf25';
  _TDHCPServerCustomOption = 'number:integer type:TEnumOpenapipf26 value:RawUtf8';
  _TDHCPServerLease = 'active_status:RawUtf8 descr:RawUtf8 ends:RawUtf8 hostname:RawUtf8 ' +
    'if:RawUtf8 ip:RawUtf8 mac:RawUtf8 online_status:RawUtf8 starts:RawUtf8';
  _TDHCPServerStaticMapping = 'arp_table_static_entry:boolean cid:RawUtf8 ' +
    'defaultleasetime:integer descr:RawUtf8 dnsserver:TRawUtf8DynArray domain:RawUtf8 ' +
    'domainsearchlist:TRawUtf8DynArray gateway:RawUtf8 hostname:RawUtf8 ipaddr:RawUtf8 ' +
    'mac:RawUtf8 maxleasetime:integer ntpserver:TRawUtf8DynArray winsserver:TRawUtf8DynArray';
  _TDNSForwarderApply = 'applied:boolean';
  _TDNSForwarderHostOverride = 'aliases:variant descr:RawUtf8 domain:RawUtf8 ' +
    'host:RawUtf8 ip:RawUtf8';
  _TDNSForwarderHostOverrideAlias = 'description:RawUtf8 domain:RawUtf8 host:RawUtf8';
  _TDNSResolverAccessList = 'action:TEnumOpenapipf27 description:RawUtf8 ' +
    'name:RawUtf8 networks:variant';
  _TDNSResolverAccessListNetwork = 'description:RawUtf8 mask:integer network:RawUtf8';
  _TDNSResolverApply = 'applied:boolean';
  _TDNSResolverDomainOverride = 'descr:RawUtf8 domain:RawUtf8 forward_tls_upstream:boolean ' +
    'ip:RawUtf8 tls_hostname:RawUtf8';
  _TDNSResolverHostOverride = 'aliases:variant descr:RawUtf8 domain:RawUtf8 ' +
    'host:RawUtf8 ip:TRawUtf8DynArray';
  _TDNSResolverHostOverrideAlias = 'descr:RawUtf8 domain:RawUtf8 host:RawUtf8';
  _TDNSResolverSettings = 'active_interface:TRawUtf8DynArray custom_options:RawUtf8 ' +
    'dnssec:boolean enable:boolean enablessl:boolean forwarding:boolean outgoing_interface:TRawUtf8DynArray ' +
    'port:RawUtf8 python:boolean python_order:TEnumOpenapipf28 python_script:RawUtf8 ' +
    'regdhcp:boolean regdhcpstatic:boolean regovpnclients:boolean sslcertref:RawUtf8 ' +
    'strictout:boolean system_domain_local_zone_type:TEnumOpenapipf29 tlsport:RawUtf8';
  _TDefaultGateway = 'defaultgw4:RawUtf8 defaultgw6:RawUtf8';
  _TEmailNotificationSettings = 'authentication_mechanism:TEnumOpenapipf30 ' +
    'disable:boolean fromaddress:RawUtf8 ipaddress:RawUtf8 notifyemailaddress:RawUtf8 ' +
    'password:RawUtf8 port:RawUtf8 ssl:boolean sslvalidate:boolean timeout:integer ' +
    'username:RawUtf8';
  _TFailedDependencyError = '_links:variant code:integer data:variant message:RawUtf8 ' +
    'response_id:RawUtf8 status:RawUtf8';
  _TFirewallAdvancedSettings = 'aliasesresolveinterval:integer checkaliasesurlcert:boolean';
  _TFirewallAlias = 'address:TRawUtf8DynArray descr:RawUtf8 detail:TRawUtf8DynArray ' +
    'name:RawUtf8 type:TEnumOpenapipf31';
  _TFirewallApply = 'applied:boolean pending_subsystems:TRawUtf8DynArray';
  _TFirewallLog = 'text:RawUtf8';
  _TFirewallRule = 'ackqueue:RawUtf8 associated_rule_id:RawUtf8 created_by:RawUtf8 ' +
    'created_time:integer defaultqueue:RawUtf8 descr:RawUtf8 destination:RawUtf8 ' +
    'destination_port:RawUtf8 direction:TEnumOpenapipf32 disabled:boolean dnpipe:RawUtf8 ' +
    'floating:boolean gateway:RawUtf8 icmptype:TEnumOpenapipf33Set interface:TRawUtf8DynArray ' +
    'ipprotocol:TEnumOpenapipf34 log:boolean pdnpipe:RawUtf8 protocol:TEnumOpenapipf35 ' +
    'quick:boolean sched:RawUtf8 source:RawUtf8 source_port:RawUtf8 statetype:TEnumOpenapipf36 ' +
    'tag:RawUtf8 tcp_flags_any:boolean tcp_flags_out_of:TEnumOpenapipf37Set ' +
    'tcp_flags_set:TEnumOpenapipf37Set tracker:integer type:TEnumOpenapipf38 ' +
    'updated_by:RawUtf8 updated_time:integer';
  _TFirewallSchedule = 'active:boolean descr:RawUtf8 name:RawUtf8 schedlabel:RawUtf8 ' +
    'timerange:variant';
  _TFirewallScheduleTimeRange = 'day:TIntegerDynArray hour:RawUtf8 month:TIntegerDynArray ' +
    'position:TIntegerDynArray rangedescr:RawUtf8';
  _TFirewallState = 'age:RawUtf8 bytes_in:integer bytes_out:integer bytes_total:integer ' +
    'destination:RawUtf8 direction:RawUtf8 expires_in:RawUtf8 interface:RawUtf8 ' +
    'packets_in:integer packets_out:integer packets_total:integer protocol:RawUtf8 ' +
    'source:RawUtf8 state:RawUtf8';
  _TFirewallStatesSize = 'currentstates:integer defaultmaximumstates:integer ' +
    'maximumstates:integer';
  _TForbiddenError = '_links:variant code:integer data:variant message:RawUtf8 ' +
    'response_id:RawUtf8 status:RawUtf8';
  _TGraphQL = 'query:RawUtf8 variables:variant';
  _TDtoOpenapipf2 = 'response_id:RawUtf8';
  _TDtoOpenapipf3 = 'column:integer line:integer';
  _TDtoOpenapipf1 = 'extensions:TDtoOpenapipf2 locations:array of TDtoOpenapipf3 ' +
    'message:RawUtf8 path:TRawUtf8DynArray';
  _TGraphQLResponse = 'data:variant errors:array of TDtoOpenapipf1';
  _THAProxyApply = 'applied:boolean';
  _THAProxyBackend = 'acls:variant actions:variant advanced:RawUtf8 advanced_backend:RawUtf8 ' +
    'agent_checks:boolean agent_inter:integer agent_port:RawUtf8 balance:TEnumOpenapipf39 ' +
    'balance_uridepth:integer balance_urilen:integer balance_uriwhole:boolean ' +
    'check_type:TEnumOpenapipf40 checkinter:integer connection_timeout:integer ' +
    'cookie_attribute_secure:boolean email_level:TEnumOpenapipf41 email_to:RawUtf8 ' +
    'errorfiles:variant haproxy_cookie_domains:TRawUtf8DynArray haproxy_cookie_dynamic_cookie_key:RawUtf8 ' +
    'haproxy_cookie_maxidle:integer haproxy_cookie_maxlife:integer httpcheck_method:TEnumOpenapipf42 ' +
    'log_health_checks:boolean monitor_domain:RawUtf8 monitor_httpversion:RawUtf8 ' +
    'monitor_uri:RawUtf8 monitor_username:RawUtf8 name:RawUtf8 persist_cookie_cachable:boolean ' +
    'persist_cookie_enabled:boolean persist_cookie_httponly:boolean persist_cookie_mode:TEnumOpenapipf43 ' +
    'persist_cookie_name:RawUtf8 persist_cookie_postonly:boolean persist_cookie_secure:boolean ' +
    'persist_stick_cookiename:RawUtf8 persist_stick_expire:RawUtf8 persist_stick_length:integer ' +
    'persist_stick_tablesize:RawUtf8 persist_sticky_type:TEnumOpenapipf44 retries:integer ' +
    'server_timeout:integer servers:variant stats_admin:RawUtf8 stats_desc:RawUtf8 ' +
    'stats_enabled:boolean stats_node:RawUtf8 stats_password:RawUtf8 stats_realm:RawUtf8 ' +
    'stats_refresh:integer stats_scope:TRawUtf8DynArray stats_uri:RawUtf8 stats_username:RawUtf8 ' +
    'strict_transport_security:integer transparent_clientip:boolean transparent_interface:RawUtf8';
  _THAProxyBackendACL = 'casesensitive:boolean expression:TEnumOpenapipf45 ' +
    'name:RawUtf8 not:boolean value:RawUtf8';
  _THAProxyBackendAction = 'acl:RawUtf8 action:TEnumOpenapipf46 customaction:RawUtf8 ' +
    'deny_status:RawUtf8 find:RawUtf8 fmt:RawUtf8 lua_function:RawUtf8 name:RawUtf8 ' +
    'path:RawUtf8 realm:RawUtf8 reason:RawUtf8 replace:RawUtf8 rule:RawUtf8 ' +
    'server:RawUtf8 status:RawUtf8';
  _THAProxyBackendErrorFile = 'errorcode:integer errorfile:RawUtf8';
  _THAProxyBackendServer = 'address:RawUtf8 name:RawUtf8 port:RawUtf8 serverid:integer ' +
    'ssl:boolean sslserververify:boolean status:TEnumOpenapipf47 weight:integer';
  _THAProxyDNSResolver = 'name:RawUtf8 port:RawUtf8 server:RawUtf8';
  _THAProxyEmailMailer = 'mailserver:RawUtf8 mailserverport:RawUtf8 name:RawUtf8';
  _THAProxyFile = 'content:RawUtf8 name:RawUtf8 type:TEnumOpenapipf48';
  _THAProxyFrontend = 'a_actionitems:variant a_errorfiles:variant a_extaddr:variant ' +
    'advanced:RawUtf8 advanced_bind:RawUtf8 backend_serverpool:RawUtf8 client_timeout:integer ' +
    'descr:RawUtf8 dontlog_normal:boolean dontlognull:boolean forwardfor:boolean ' +
    'ha_acls:variant httpclose:TEnumOpenapipf49 log_detailed:boolean log_separate_errors:boolean ' +
    'max_connections:integer name:RawUtf8 socket_stats:boolean status:TEnumOpenapipf2 ' +
    'type:TEnumOpenapipf50';
  _THAProxyFrontendACL = 'casesensitive:boolean expression:TEnumOpenapipf45 ' +
    'name:RawUtf8 not:boolean value:RawUtf8';
  _THAProxyFrontendAction = 'acl:RawUtf8 action:TEnumOpenapipf51 backend:RawUtf8 ' +
    'customaction:RawUtf8 deny_status:RawUtf8 find:RawUtf8 fmt:RawUtf8 lua_function:RawUtf8 ' +
    'name:RawUtf8 path:RawUtf8 realm:RawUtf8 reason:RawUtf8 replace:RawUtf8 ' +
    'rule:RawUtf8 status:RawUtf8';
  _THAProxyFrontendAddress = 'exaddr_advanced:RawUtf8 extaddr:TEnumOpenapipf52 ' +
    'extaddr_custom:RawUtf8 extaddr_port:RawUtf8 extaddr_ssl:boolean';
  _THAProxyFrontendErrorFile = 'errorcode:integer errorfile:RawUtf8';
  _THAProxySettings = 'advanced:RawUtf8 carpdev:RawUtf8 dns_resolvers:variant ' +
    'email_from:RawUtf8 email_level:TEnumOpenapipf53 email_mailers:variant email_myhostname:RawUtf8 ' +
    'email_to:RawUtf8 enable:boolean enablesync:boolean hard_stop_after:RawUtf8 ' +
    'localstats_refreshtime:integer localstats_sticktable_refreshtime:integer ' +
    'localstatsport:RawUtf8 log_send_hostname:RawUtf8 logfacility:TEnumOpenapipf54 ' +
    'loglevel:TEnumOpenapipf55 maxconn:integer nbthread:integer remotesyslog:RawUtf8 ' +
    'resolver_holdvalid:RawUtf8 resolver_retries:integer resolver_timeoutretry:RawUtf8 ' +
    'sslcompatibilitymode:TEnumOpenapipf56 ssldefaultdhparam:integer terminate_on_reload:boolean';
  _TIPsecApply = 'applied:boolean';
  _TIPsecChildSAStatus = 'bytes_in:integer bytes_out:integer dh_group:RawUtf8 ' +
    'encap:boolean encr_alg:RawUtf8 encr_keysize:integer install_time:integer ' +
    'integ_alg:RawUtf8 life_time:integer local_ts:TRawUtf8DynArray mode:RawUtf8 ' +
    'name:RawUtf8 packets_in:integer packets_out:integer protocol:RawUtf8 rekey_time:integer ' +
    'remote_ts:TRawUtf8DynArray reqid:integer spi_in:RawUtf8 spi_out:RawUtf8 ' +
    'state:RawUtf8 uniqueid:integer use_in:integer use_out:integer';
  _TIPsecPhase1 = 'authentication_method:TEnumOpenapipf57 caref:RawUtf8 certref:RawUtf8 ' +
    'closeaction:TEnumOpenapipf58 descr:RawUtf8 disabled:boolean dpd_delay:integer ' +
    'dpd_maxfail:integer encryption:variant gw_duplicates:boolean ikeid:integer ' +
    'ikeport:RawUtf8 iketype:TEnumOpenapipf59 interface:RawUtf8 lifetime:integer ' +
    'mobike:boolean mode:TEnumOpenapipf60 myid_data:RawUtf8 myid_type:TEnumOpenapipf61 ' +
    'nat_traversal:TEnumOpenapipf62 nattport:RawUtf8 peerid_data:RawUtf8 peerid_type:TEnumOpenapipf63 ' +
    'pre_shared_key:RawUtf8 prfselect_enable:boolean protocol:TEnumOpenapipf64 ' +
    'rand_time:integer reauth_time:integer rekey_time:integer remote_gateway:RawUtf8 ' +
    'splitconn:boolean startaction:TEnumOpenapipf58';
  _TIPsecPhase1Encryption = 'dhgroup:integer encryption_algorithm_keylen:integer ' +
    'encryption_algorithm_name:TEnumOpenapipf65 hash_algorithm:TEnumOpenapipf66 ' +
    'prf_algorithm:TEnumOpenapipf66';
  _TIPsecPhase2 = 'descr:RawUtf8 disabled:boolean encryption_algorithm_option:variant ' +
    'hash_algorithm_option:TEnumOpenapipf67Set ikeid:integer keepalive:boolean ' +
    'lifetime:integer localid_address:RawUtf8 localid_netbits:integer localid_type:RawUtf8 ' +
    'mode:TEnumOpenapipf68 natlocalid_address:RawUtf8 natlocalid_netbits:integer ' +
    'natlocalid_type:RawUtf8 pfsgroup:integer pinghost:RawUtf8 protocol:TEnumOpenapipf69 ' +
    'rand_time:integer rekey_time:integer remoteid_address:RawUtf8 remoteid_netbits:integer ' +
    'remoteid_type:RawUtf8 reqid:integer uniqid:RawUtf8';
  _TIPsecPhase2Encryption = 'keylen:integer name:TEnumOpenapipf65';
  _TIPsecSAStatus = 'child_sas:variant con_id:RawUtf8 dh_group:RawUtf8 encr_alg:RawUtf8 ' +
    'encr_keysize:integer established:integer initiator_spi:RawUtf8 integ_alg:RawUtf8 ' +
    'local_host:RawUtf8 local_id:RawUtf8 local_port:RawUtf8 nat_any:boolean ' +
    'nat_remote:boolean prf_alg:RawUtf8 rekey_time:integer remote_host:RawUtf8 ' +
    'remote_id:RawUtf8 remote_port:RawUtf8 responder_spi:RawUtf8 state:RawUtf8 ' +
    'uniqueid:integer version:integer';
  _TInterfaceApply = 'applied:boolean pending_interfaces:TRawUtf8DynArray';
  _TInterfaceBridge = 'bridgeif:RawUtf8 descr:RawUtf8 members:TRawUtf8DynArray';
  _TInterfaceGRE = 'add_static_route:boolean descr:RawUtf8 greif:RawUtf8 ' +
    'if:RawUtf8 remote_addr:RawUtf8 tunnel_local_addr:RawUtf8 tunnel_local_addr6:RawUtf8 ' +
    'tunnel_remote_addr:RawUtf8 tunnel_remote_addr6:RawUtf8 tunnel_remote_net:integer ' +
    'tunnel_remote_net6:integer';
  _TInterfaceGroup = 'descr:RawUtf8 ifname:RawUtf8 members:TRawUtf8DynArray';
  _TInterfaceLAGG = 'descr:RawUtf8 failovermaster:RawUtf8 lacptimeout:TEnumOpenapipf70 ' +
    'lagghash:TEnumOpenapipf71 laggif:RawUtf8 members:TRawUtf8DynArray proto:TEnumOpenapipf72';
  _TInterfaceStats = 'collisions:integer descr:RawUtf8 dhcplink:RawUtf8 enable:boolean ' +
    'gateway:RawUtf8 gatewayv6:RawUtf8 hwif:RawUtf8 inbytes:integer inbytespass:integer ' +
    'inerrs:integer inpkts:integer inpktspass:integer ipaddr:RawUtf8 ipaddrv6:RawUtf8 ' +
    'linklocal:RawUtf8 macaddr:RawUtf8 media:RawUtf8 mtu:RawUtf8 name:RawUtf8 ' +
    'outbytes:integer outbytespass:integer outerrs:integer outpkts:integer outpktspass:integer ' +
    'status:RawUtf8 subnet:RawUtf8 subnetv6:RawUtf8';
  _TInterfaceVLAN = 'descr:RawUtf8 if:RawUtf8 pcp:integer tag:integer vlanif:RawUtf8';
  _TLogSettings = 'auth:boolean dhcp:boolean disablelocallogging:boolean ' +
    'dpinger:boolean enableremotelogging:boolean filter:boolean filterdescriptions:integer ' +
    'format:TEnumOpenapipf73 hostapd:boolean ipprotocol:TEnumOpenapipf74 logall:boolean ' +
    'logcompressiontype:TEnumOpenapipf75 logconfigchanges:boolean logfilesize:integer ' +
    'nentries:integer nologbogons:boolean nologdefaultblock:boolean nologdefaultpass:boolean ' +
    'nolognginx:boolean nologprivatenets:boolean ntpd:boolean portalauth:boolean ' +
    'ppp:boolean rawfilter:boolean remoteserver:RawUtf8 remoteserver2:RawUtf8 ' +
    'remoteserver3:RawUtf8 resolver:boolean reverseorder:boolean rotatecount:integer ' +
    'routing:boolean sourceip:RawUtf8 system:boolean vpn:boolean';
  _TMediaTypeError = '_links:variant code:integer data:variant message:RawUtf8 ' +
    'response_id:RawUtf8 status:RawUtf8';
  _TMethodNotAllowedError = '_links:variant code:integer data:variant message:RawUtf8 ' +
    'response_id:RawUtf8 status:RawUtf8';
  _TNTPSettings = 'clockstats:boolean dnsresolv:TEnumOpenapipf76 enable:boolean ' +
    'interface:TRawUtf8DynArray leapsec:RawUtf8 logpeer:boolean logsys:boolean ' +
    'loopstats:boolean ntpmaxpeers:integer ntpmaxpoll:TEnumOpenapipf77 ntpminpoll:TEnumOpenapipf77 ' +
    'orphan:integer peerstats:boolean serverauth:boolean serverauthalgo:TEnumOpenapipf78 ' +
    'serverauthkey:RawUtf8 statsgraph:boolean';
  _TNTPTimeServer = 'noselect:boolean prefer:boolean timeserver:RawUtf8 type:TEnumOpenapipf79';
  _TNetworkInterface = 'adv_dhcp_config_advanced:boolean adv_dhcp_config_file_override:boolean ' +
    'adv_dhcp_config_file_override_path:RawUtf8 adv_dhcp_option_modifiers:RawUtf8 ' +
    'adv_dhcp_pt_backoff_cutoff:integer adv_dhcp_pt_initial_interval:integer ' +
    'adv_dhcp_pt_reboot:integer adv_dhcp_pt_retry:integer adv_dhcp_pt_select_timeout:integer ' +
    'adv_dhcp_pt_timeout:integer adv_dhcp_pt_values:TEnumOpenapipf80 adv_dhcp_request_options:RawUtf8 ' +
    'adv_dhcp_required_options:RawUtf8 adv_dhcp_send_options:RawUtf8 alias_address:RawUtf8 ' +
    'alias_subnet:integer blockbogons:boolean blockpriv:boolean descr:RawUtf8 ' +
    'dhcphostname:RawUtf8 dhcprejectfrom:TRawUtf8DynArray enable:boolean gateway:RawUtf8 ' +
    'gateway_6rd:RawUtf8 gatewayv6:RawUtf8 if:RawUtf8 ipaddr:RawUtf8 ipaddrv6:RawUtf8 ' +
    'ipv6usev4iface:boolean media:RawUtf8 mediaopt:RawUtf8 mss:integer mtu:integer ' +
    'prefix_6rd:RawUtf8 prefix_6rd_v4plen:integer slaacusev4iface:boolean spoofmac:RawUtf8 ' +
    'subnet:integer subnetv6:integer track6_interface:RawUtf8 track6_prefix_id_hex:RawUtf8 ' +
    'typev4:TEnumOpenapipf81 typev6:TEnumOpenapipf82';
  _TNotAcceptableError = '_links:variant code:integer data:variant message:RawUtf8 ' +
    'response_id:RawUtf8 status:RawUtf8';
  _TNotFoundError = '_links:variant code:integer data:variant message:RawUtf8 ' +
    'response_id:RawUtf8 status:RawUtf8';
  _TOneToOneNATMapping = 'descr:RawUtf8 destination:RawUtf8 disabled:boolean ' +
    'external:RawUtf8 interface:RawUtf8 ipprotocol:TEnumOpenapipf83 natreflection:TEnumOpenapipf7 ' +
    'nobinat:boolean source:RawUtf8';
  _TOpenVPNClient = 'allow_compression:TEnumOpenapipf84 auth_pass:RawUtf8 ' +
    'auth_retry_none:boolean auth_user:RawUtf8 caref:RawUtf8 certref:RawUtf8 ' +
    'create_gw:TEnumOpenapipf85 custom_options:TRawUtf8DynArray data_ciphers:TRawUtf8DynArray ' +
    'data_ciphers_fallback:RawUtf8 description:RawUtf8 dev_mode:TEnumOpenapipf86 ' +
    'digest:RawUtf8 disable:boolean dns_add:boolean exit_notify:TEnumOpenapipf87 ' +
    'inactive_seconds:integer interface:RawUtf8 keepalive_interval:integer keepalive_timeout:integer ' +
    'local_port:RawUtf8 mode:TEnumOpenapipf88 passtos:boolean ping_action:TEnumOpenapipf89 ' +
    'ping_action_seconds:integer ping_method:TEnumOpenapipf90 ping_seconds:integer ' +
    'protocol:TEnumOpenapipf91 proxy_addr:RawUtf8 proxy_authtype:TEnumOpenapipf92 ' +
    'proxy_passwd:RawUtf8 proxy_port:RawUtf8 proxy_user:RawUtf8 remote_cert_tls:boolean ' +
    'remote_network:TRawUtf8DynArray remote_networkv6:TRawUtf8DynArray route_no_exec:boolean ' +
    'route_no_pull:boolean server_addr:RawUtf8 server_port:RawUtf8 sndrcvbuf:integer ' +
    'tls:RawUtf8 tls_type:TEnumOpenapipf93 tlsauth_keydir:TEnumOpenapipf94 topology:TEnumOpenapipf95 ' +
    'tunnel_network:RawUtf8 tunnel_networkv6:RawUtf8 udp_fast_io:boolean use_shaper:integer ' +
    'verbosity_level:integer vpnid:integer vpnif:RawUtf8';
  _TOpenVPNClientSpecificOverride = 'block:boolean common_name:RawUtf8 custom_options:TRawUtf8DynArray ' +
    'description:RawUtf8 disable:boolean dns_domain:RawUtf8 dns_server1:RawUtf8 ' +
    'dns_server2:RawUtf8 dns_server3:RawUtf8 dns_server4:RawUtf8 gwredir:boolean ' +
    'local_network:TRawUtf8DynArray local_networkv6:TRawUtf8DynArray netbios_enable:boolean ' +
    'netbios_ntype:integer netbios_scope:RawUtf8 ntp_server1:RawUtf8 ntp_server2:RawUtf8 ' +
    'push_reset:boolean remote_network:TRawUtf8DynArray remote_networkv6:TRawUtf8DynArray ' +
    'remove_route:boolean server_list:TRawUtf8DynArray tunnel_network:RawUtf8 ' +
    'tunnel_networkv6:RawUtf8 wins_server1:RawUtf8 wins_server2:RawUtf8';
  _TOpenVPNClientStatus = 'connect_time:RawUtf8 local_host:RawUtf8 local_port:RawUtf8 ' +
    'mgmt:RawUtf8 name:RawUtf8 port:RawUtf8 remote_host:RawUtf8 remote_port:RawUtf8 ' +
    'state:RawUtf8 state_detail:RawUtf8 status:RawUtf8 virtual_addr:RawUtf8 ' +
    'virtual_addr6:RawUtf8 vpnid:integer';
  _TOpenVPNServer = 'allow_compression:TEnumOpenapipf84 authmode:TRawUtf8DynArray ' +
    'caref:RawUtf8 cert_depth:integer certref:RawUtf8 client2client:boolean ' +
    'connlimit:integer create_gw:TEnumOpenapipf85 custom_options:TRawUtf8DynArray ' +
    'data_ciphers:TRawUtf8DynArray data_ciphers_fallback:RawUtf8 description:RawUtf8 ' +
    'dev_mode:TEnumOpenapipf86 dh_length:RawUtf8 digest:RawUtf8 disable:boolean ' +
    'dns_domain:RawUtf8 dns_server1:RawUtf8 dns_server2:RawUtf8 dns_server3:RawUtf8 ' +
    'dns_server4:RawUtf8 duplicate_cn:boolean dynamic_ip:boolean ecdh_curve:RawUtf8 ' +
    'gwredir:boolean gwredir6:boolean inactive_seconds:integer interface:RawUtf8 ' +
    'keepalive_interval:integer keepalive_timeout:integer local_network:TRawUtf8DynArray ' +
    'local_networkv6:TRawUtf8DynArray local_port:RawUtf8 maxclients:integer ' +
    'mode:TEnumOpenapipf96 netbios_enable:boolean netbios_ntype:integer netbios_scope:RawUtf8 ' +
    'ntp_server1:RawUtf8 ntp_server2:RawUtf8 passtos:boolean ping_action:TEnumOpenapipf89 ' +
    'ping_action_push:boolean ping_action_seconds:integer ping_method:TEnumOpenapipf90 ' +
    'ping_push:boolean ping_seconds:integer protocol:TEnumOpenapipf91 push_blockoutsidedns:boolean ' +
    'push_register_dns:boolean remote_cert_tls:boolean remote_network:TRawUtf8DynArray ' +
    'remote_networkv6:TRawUtf8DynArray serverbridge_dhcp:boolean serverbridge_dhcp_end:RawUtf8 ' +
    'serverbridge_dhcp_start:RawUtf8 serverbridge_interface:RawUtf8 serverbridge_routegateway:boolean ' +
    'sndrcvbuf:integer strictusercn:boolean tls:RawUtf8 tls_type:TEnumOpenapipf93 ' +
    'tlsauth_keydir:TEnumOpenapipf94 topology:TEnumOpenapipf95 tunnel_network:RawUtf8 ' +
    'tunnel_networkv6:RawUtf8 use_tls:boolean username_as_common_name:boolean ' +
    'verbosity_level:integer vpnid:integer vpnif:RawUtf8 wins_server1:RawUtf8 ' +
    'wins_server2:RawUtf8';
  _TOpenVPNServerConnectionStatus = 'bytes_recv:integer bytes_sent:integer ' +
    'cipher:RawUtf8 client_id:integer common_name:RawUtf8 connect_time:RawUtf8 ' +
    'connect_time_unix:integer peer_id:integer remote_host:RawUtf8 user_name:RawUtf8 ' +
    'virtual_addr:RawUtf8 virtual_addr6:RawUtf8';
  _TOpenVPNServerRouteStatus = 'common_name:RawUtf8 last_time:RawUtf8 remote_host:RawUtf8 ' +
    'virtual_addr:RawUtf8';
  _TOpenVPNServerStatus = 'conns:variant mgmt:RawUtf8 mode:RawUtf8 name:RawUtf8 ' +
    'port:RawUtf8 routes:variant vpnid:integer';
  _TOutboundNATMapping = 'descr:RawUtf8 destination:RawUtf8 destination_port:RawUtf8 ' +
    'disabled:boolean interface:RawUtf8 nat_port:RawUtf8 nonat:boolean nosync:boolean ' +
    'poolopts:TEnumOpenapipf97 protocol:TEnumOpenapipf98 source:RawUtf8 source_hash_key:RawUtf8 ' +
    'source_port:RawUtf8 static_nat_port:boolean target:RawUtf8 target_subnet:integer';
  _TOutboundNATMode = 'mode:TEnumOpenapipf99';
  _TPackage = 'descr:RawUtf8 installed_version:RawUtf8 latest_version:RawUtf8 ' +
    'name:RawUtf8 shortname:RawUtf8 update_available:boolean';
  _TPortForward = 'associated_rule_id:RawUtf8 created_by:RawUtf8 created_time:integer ' +
    'descr:RawUtf8 destination:RawUtf8 destination_port:RawUtf8 disabled:boolean ' +
    'interface:RawUtf8 ipprotocol:TEnumOpenapipf34 local_port:RawUtf8 natreflection:TEnumOpenapipf100 ' +
    'nordr:boolean nosync:boolean protocol:TEnumOpenapipf98 source:RawUtf8 source_port:RawUtf8 ' +
    'target:RawUtf8 updated_by:RawUtf8 updated_time:integer';
  _TRESTAPIAccessListEntry = 'descr:RawUtf8 network:RawUtf8 sched:RawUtf8 ' +
    'type:TEnumOpenapipf101 users:TRawUtf8DynArray weight:integer';
  _TRESTAPIJWT = 'token:RawUtf8';
  _TRESTAPIKey = 'descr:RawUtf8 hash:RawUtf8 hash_algo:TEnumOpenapipf102 ' +
    'key:RawUtf8 length_bytes:integer username:RawUtf8';
  _TRESTAPISettings = 'allow_pre_releases:boolean allowed_interfaces:TRawUtf8DynArray ' +
    'auth_methods:TRawUtf8DynArray enabled:boolean expose_sensitive_fields:boolean ' +
    'ha_sync:boolean ha_sync_hosts:TRawUtf8DynArray ha_sync_password:RawUtf8 ' +
    'ha_sync_username:RawUtf8 ha_sync_validate_certs:boolean hateoas:boolean ' +
    'jwt_exp:integer keep_backup:boolean log_successful_auth:boolean login_protection:boolean ' +
    'override_sensitive_fields:TRawUtf8DynArray read_only:boolean represent_interfaces_as:TEnumOpenapipf103';
  _TRESTAPISettingsSync = 'sync_data:RawUtf8';
  _TRESTAPIVersion = 'available_versions:TRawUtf8DynArray current_version:RawUtf8 ' +
    'install_version:RawUtf8 latest_version:RawUtf8 latest_version_release_date:RawUtf8 ' +
    'update_available:boolean';
  _TRoutingApply = 'applied:boolean';
  _TRoutingGateway = 'action_disable:boolean alert_interval:integer data_payload:integer ' +
    'descr:RawUtf8 disabled:boolean dpinger_dont_add_static_route:boolean force_down:boolean ' +
    'gateway:RawUtf8 gw_down_kill_states:TEnumOpenapipf104 interface:RawUtf8 ' +
    'interval:integer ipprotocol:TEnumOpenapipf83 latencyhigh:integer latencylow:integer ' +
    'loss_interval:integer losshigh:integer losslow:integer monitor:RawUtf8 ' +
    'monitor_disable:boolean name:RawUtf8 nonlocalgateway:boolean time_period:integer ' +
    'weight:integer';
  _TRoutingGatewayGroup = 'descr:RawUtf8 ipprotocol:RawUtf8 name:RawUtf8 ' +
    'priorities:variant trigger:TEnumOpenapipf105';
  _TRoutingGatewayGroupPriority = 'gateway:RawUtf8 tier:integer virtual_ip:RawUtf8';
  _TRoutingGatewayStatus = 'delay:single loss:single monitorip:RawUtf8 name:RawUtf8 ' +
    'srcip:RawUtf8 status:RawUtf8 stddev:single substatus:RawUtf8';
  _TSSH = 'enable:boolean port:RawUtf8 sshdagentforwarding:boolean sshdkeyonly:TEnumOpenapipf106';
  _TServerError = '_links:variant code:integer data:variant message:RawUtf8 ' +
    'response_id:RawUtf8 status:RawUtf8';
  _TService = 'action:TEnumOpenapipf107 description:RawUtf8 enabled:boolean ' +
    'name:RawUtf8 status:boolean';
  _TServiceUnavailableError = '_links:variant code:integer data:variant message:RawUtf8 ' +
    'response_id:RawUtf8 status:RawUtf8';
  _TServiceWatchdog = 'description:RawUtf8 enabled:boolean name:RawUtf8 notify:boolean';
  _TStaticRoute = 'descr:RawUtf8 disabled:boolean gateway:RawUtf8 network:RawUtf8';
  _TSuccess = '_links:variant code:integer data:variant message:RawUtf8 response_id:RawUtf8 ' +
    'status:RawUtf8';
  _TSystemConsole = 'passwd_protect_console:boolean';
  _TSystemDNS = 'dnsallowoverride:boolean dnslocalhost:TEnumOpenapipf108 ' +
    'dnsserver:TRawUtf8DynArray';
  _TSystemHalt = 'dry_run:boolean';
  _TSystemHostname = 'domain:RawUtf8 hostname:RawUtf8';
  _TSystemLog = 'text:RawUtf8';
  _TSystemReboot = 'dry_run:boolean';
  _TSystemStatus = 'bios_date:RawUtf8 bios_vendor:RawUtf8 bios_version:RawUtf8 ' +
    'cpu_count:integer cpu_load_avg:TSingleDynArray cpu_model:RawUtf8 cpu_usage:single ' +
    'disk_usage:single kernel_pti:boolean mbuf_usage:single mds_mitigation:RawUtf8 ' +
    'mem_usage:single netgate_id:RawUtf8 platform:RawUtf8 serial:RawUtf8 swap_usage:single ' +
    'temp_c:single temp_f:single uptime:RawUtf8';
  _TSystemTunable = 'descr:RawUtf8 tunable:RawUtf8 value:RawUtf8';
  _TSystemVersion = 'base:RawUtf8 buildtime:RawUtf8 patch:RawUtf8 version:RawUtf8';
  _TTrafficShaper = 'bandwidth:integer bandwidthtype:TEnumOpenapipf109 enabled:boolean ' +
    'interface:RawUtf8 name:RawUtf8 qlimit:integer queue:variant scheduler:TEnumOpenapipf110 ' +
    'tbrconfig:integer';
  _TTrafficShaperLimiter = 'aqm:TEnumOpenapipf111 bandwidth:variant buckets:integer ' +
    'delay:integer description:RawUtf8 ecn:boolean enabled:boolean mask:TEnumOpenapipf112 ' +
    'maskbits:integer maskbitsv6:integer name:RawUtf8 number:integer param_codel_interval:integer ' +
    'param_codel_target:integer param_fq_codel_flows:integer param_fq_codel_interval:integer ' +
    'param_fq_codel_limit:integer param_fq_codel_quantum:integer param_fq_codel_target:integer ' +
    'param_fq_pie_alpha:integer param_fq_pie_beta:integer param_fq_pie_flows:integer ' +
    'param_fq_pie_limit:integer param_fq_pie_max_burst:integer param_fq_pie_max_ecnth:integer ' +
    'param_fq_pie_quantum:integer param_fq_pie_target:integer param_fq_pie_tupdate:integer ' +
    'param_gred_max_p:integer param_gred_max_th:integer param_gred_min_th:integer ' +
    'param_gred_w_q:integer param_pie_alpha:integer param_pie_beta:integer param_pie_max_burst:integer ' +
    'param_pie_max_ecnth:integer param_pie_target:integer param_pie_tupdate:integer ' +
    'param_red_max_p:integer param_red_max_th:integer param_red_min_th:integer ' +
    'param_red_w_q:integer pie_capdrop:boolean pie_onoff:boolean pie_pderand:boolean ' +
    'pie_qdelay:boolean plr:single qlimit:integer queue:variant sched:TEnumOpenapipf113';
  _TTrafficShaperLimiterBandwidth = 'bw:integer bwscale:TEnumOpenapipf114 ' +
    'bwsched:RawUtf8';
  _TTrafficShaperLimiterQueue = 'aqm:TEnumOpenapipf111 buckets:integer description:RawUtf8 ' +
    'ecn:boolean enabled:boolean mask:TEnumOpenapipf112 maskbits:integer maskbitsv6:integer ' +
    'name:RawUtf8 number:integer param_codel_interval:integer param_codel_target:integer ' +
    'param_gred_max_p:integer param_gred_max_th:integer param_gred_min_th:integer ' +
    'param_gred_w_q:integer param_pie_alpha:integer param_pie_beta:integer param_pie_max_burst:integer ' +
    'param_pie_max_ecnth:integer param_pie_target:integer param_pie_tupdate:integer ' +
    'param_red_max_p:integer param_red_max_th:integer param_red_min_th:integer ' +
    'param_red_w_q:integer pie_capdrop:boolean pie_onoff:boolean pie_pderand:boolean ' +
    'pie_qdelay:boolean plr:single qlimit:integer weight:integer';
  _TTrafficShaperQueue = 'bandwidth:integer bandwidthtype:TEnumOpenapipf109 ' +
    'borrow:boolean buckets:integer codel:boolean default:boolean description:RawUtf8 ' +
    'ecn:boolean enabled:boolean hogs:integer interface:RawUtf8 linkshare:boolean ' +
    'linkshare_d:integer linkshare_m1:RawUtf8 linkshare_m2:RawUtf8 name:RawUtf8 ' +
    'priority:integer qlimit:integer realtime:boolean realtime_d:integer realtime_m1:RawUtf8 ' +
    'realtime_m2:RawUtf8 red:boolean rio:boolean upperlimit:boolean upperlimit_d:integer ' +
    'upperlimit_m1:RawUtf8 upperlimit_m2:RawUtf8';
  _TUnprocessableContentError = '_links:variant code:integer data:variant ' +
    'message:RawUtf8 response_id:RawUtf8 status:RawUtf8';
  _TUser = 'authorizedkeys:RawUtf8 cert:TRawUtf8DynArray descr:RawUtf8 disabled:boolean ' +
    'expires:RawUtf8 ipsecpsk:RawUtf8 name:RawUtf8 password:RawUtf8 priv:TRawUtf8DynArray ' +
    'scope:RawUtf8 uid:integer';
  _TUserGroup = 'description:RawUtf8 gid:integer member:TRawUtf8DynArray ' +
    'name:RawUtf8 priv:TRawUtf8DynArray scope:TEnumOpenapipf108';
  _TVirtualIP = 'advbase:integer advskew:integer carp_mode:TEnumOpenapipf115 ' +
    'carp_peer:RawUtf8 carp_status:RawUtf8 descr:RawUtf8 interface:RawUtf8 mode:TEnumOpenapipf116 ' +
    'noexpand:boolean password:RawUtf8 subnet:RawUtf8 subnet_bits:integer type:TEnumOpenapipf117 ' +
    'uniqid:RawUtf8 vhid:integer';
  _TVirtualIPApply = 'applied:boolean';
  _TWakeOnLANSend = 'interface:RawUtf8 mac_addr:RawUtf8';
  _TWebGUISettings = 'port:RawUtf8 protocol:TEnumOpenapipf16 sslcertref:RawUtf8';
  _TWireGuardApply = 'applied:boolean';
  _TWireGuardPeer = 'allowedips:variant descr:RawUtf8 enabled:boolean endpoint:RawUtf8 ' +
    'persistentkeepalive:integer port:RawUtf8 presharedkey:RawUtf8 publickey:RawUtf8 ' +
    'tun:RawUtf8';
  _TWireGuardPeerAllowedIP = 'address:RawUtf8 descr:RawUtf8 mask:integer';
  _TWireGuardSettings = 'enable:boolean hide_peers:boolean hide_secrets:boolean ' +
    'interface_group:TEnumOpenapipf118 keep_conf:boolean resolve_interval:integer ' +
    'resolve_interval_track:boolean';
  _TWireGuardTunnel = 'addresses:variant enabled:boolean listenport:RawUtf8 ' +
    'mtu:integer name:RawUtf8 privatekey:RawUtf8 publickey:RawUtf8';
  _TWireGuardTunnelAddress = 'address:RawUtf8 descr:RawUtf8 mask:integer';


procedure RegisterRtti;
begin
  TRttiJson.RegisterCustomEnumValues([
    TypeInfo(TEnumOpenapipf1), nil, @ENUMOPENAPIPF1_TXT,
    TypeInfo(TEnumOpenapipf2), nil, @ENUMOPENAPIPF2_TXT,
    TypeInfo(TEnumOpenapipf3), nil, @ENUMOPENAPIPF3_TXT,
    TypeInfo(TEnumOpenapipf4), nil, @ENUMOPENAPIPF4_TXT,
    TypeInfo(TEnumOpenapipf5), nil, @ENUMOPENAPIPF5_TXT,
    TypeInfo(TEnumOpenapipf6), nil, @ENUMOPENAPIPF6_TXT,
    TypeInfo(TEnumOpenapipf7), nil, @ENUMOPENAPIPF7_TXT,
    TypeInfo(TEnumOpenapipf8), nil, @ENUMOPENAPIPF8_TXT,
    TypeInfo(TEnumOpenapipf9), nil, @ENUMOPENAPIPF9_TXT,
    TypeInfo(TEnumOpenapipf10), nil, @ENUMOPENAPIPF10_TXT,
    TypeInfo(TEnumOpenapipf11), nil, @ENUMOPENAPIPF11_TXT,
    TypeInfo(TEnumOpenapipf12), nil, @ENUMOPENAPIPF12_TXT,
    TypeInfo(TEnumOpenapipf13), nil, @ENUMOPENAPIPF13_TXT,
    TypeInfo(TEnumOpenapipf14), TypeInfo(TEnumOpenapipf14Set), @ENUMOPENAPIPF14_TXT,
    TypeInfo(TEnumOpenapipf15), nil, @ENUMOPENAPIPF15_TXT,
    TypeInfo(TEnumOpenapipf16), nil, @ENUMOPENAPIPF16_TXT,
    TypeInfo(TEnumOpenapipf17), nil, @ENUMOPENAPIPF17_TXT,
    TypeInfo(TEnumOpenapipf18), nil, @ENUMOPENAPIPF18_TXT,
    TypeInfo(TEnumOpenapipf19), nil, @ENUMOPENAPIPF19_TXT,
    TypeInfo(TEnumOpenapipf20), nil, @ENUMOPENAPIPF20_TXT,
    TypeInfo(TEnumOpenapipf21), nil, @ENUMOPENAPIPF21_TXT,
    TypeInfo(TEnumOpenapipf22), nil, @ENUMOPENAPIPF22_TXT,
    TypeInfo(TEnumOpenapipf23), nil, @ENUMOPENAPIPF23_TXT,
    TypeInfo(TEnumOpenapipf24), nil, @ENUMOPENAPIPF24_TXT,
    TypeInfo(TEnumOpenapipf25), nil, @ENUMOPENAPIPF25_TXT,
    TypeInfo(TEnumOpenapipf26), nil, @ENUMOPENAPIPF26_TXT,
    TypeInfo(TEnumOpenapipf27), nil, @ENUMOPENAPIPF27_TXT,
    TypeInfo(TEnumOpenapipf28), nil, @ENUMOPENAPIPF28_TXT,
    TypeInfo(TEnumOpenapipf29), nil, @ENUMOPENAPIPF29_TXT,
    TypeInfo(TEnumOpenapipf30), nil, @ENUMOPENAPIPF30_TXT,
    TypeInfo(TEnumOpenapipf31), nil, @ENUMOPENAPIPF31_TXT,
    TypeInfo(TEnumOpenapipf32), nil, @ENUMOPENAPIPF32_TXT,
    TypeInfo(TEnumOpenapipf33), TypeInfo(TEnumOpenapipf33Set), @ENUMOPENAPIPF33_TXT,
    TypeInfo(TEnumOpenapipf34), nil, @ENUMOPENAPIPF34_TXT,
    TypeInfo(TEnumOpenapipf35), nil, @ENUMOPENAPIPF35_TXT,
    TypeInfo(TEnumOpenapipf36), nil, @ENUMOPENAPIPF36_TXT,
    TypeInfo(TEnumOpenapipf37), TypeInfo(TEnumOpenapipf37Set), @ENUMOPENAPIPF37_TXT,
    TypeInfo(TEnumOpenapipf38), nil, @ENUMOPENAPIPF38_TXT,
    TypeInfo(TEnumOpenapipf39), nil, @ENUMOPENAPIPF39_TXT,
    TypeInfo(TEnumOpenapipf40), nil, @ENUMOPENAPIPF40_TXT,
    TypeInfo(TEnumOpenapipf41), nil, @ENUMOPENAPIPF41_TXT,
    TypeInfo(TEnumOpenapipf42), nil, @ENUMOPENAPIPF42_TXT,
    TypeInfo(TEnumOpenapipf43), nil, @ENUMOPENAPIPF43_TXT,
    TypeInfo(TEnumOpenapipf44), nil, @ENUMOPENAPIPF44_TXT,
    TypeInfo(TEnumOpenapipf45), nil, @ENUMOPENAPIPF45_TXT,
    TypeInfo(TEnumOpenapipf46), nil, @ENUMOPENAPIPF46_TXT,
    TypeInfo(TEnumOpenapipf47), nil, @ENUMOPENAPIPF47_TXT,
    TypeInfo(TEnumOpenapipf48), nil, @ENUMOPENAPIPF48_TXT,
    TypeInfo(TEnumOpenapipf49), nil, @ENUMOPENAPIPF49_TXT,
    TypeInfo(TEnumOpenapipf50), nil, @ENUMOPENAPIPF50_TXT,
    TypeInfo(TEnumOpenapipf51), nil, @ENUMOPENAPIPF51_TXT,
    TypeInfo(TEnumOpenapipf52), nil, @ENUMOPENAPIPF52_TXT,
    TypeInfo(TEnumOpenapipf53), nil, @ENUMOPENAPIPF53_TXT,
    TypeInfo(TEnumOpenapipf54), nil, @ENUMOPENAPIPF54_TXT,
    TypeInfo(TEnumOpenapipf55), nil, @ENUMOPENAPIPF55_TXT,
    TypeInfo(TEnumOpenapipf56), nil, @ENUMOPENAPIPF56_TXT,
    TypeInfo(TEnumOpenapipf57), nil, @ENUMOPENAPIPF57_TXT,
    TypeInfo(TEnumOpenapipf58), nil, @ENUMOPENAPIPF58_TXT,
    TypeInfo(TEnumOpenapipf59), nil, @ENUMOPENAPIPF59_TXT,
    TypeInfo(TEnumOpenapipf60), nil, @ENUMOPENAPIPF60_TXT,
    TypeInfo(TEnumOpenapipf61), nil, @ENUMOPENAPIPF61_TXT,
    TypeInfo(TEnumOpenapipf62), nil, @ENUMOPENAPIPF62_TXT,
    TypeInfo(TEnumOpenapipf63), nil, @ENUMOPENAPIPF63_TXT,
    TypeInfo(TEnumOpenapipf64), nil, @ENUMOPENAPIPF64_TXT,
    TypeInfo(TEnumOpenapipf65), nil, @ENUMOPENAPIPF65_TXT,
    TypeInfo(TEnumOpenapipf66), nil, @ENUMOPENAPIPF66_TXT,
    TypeInfo(TEnumOpenapipf67), TypeInfo(TEnumOpenapipf67Set), @ENUMOPENAPIPF67_TXT,
    TypeInfo(TEnumOpenapipf68), nil, @ENUMOPENAPIPF68_TXT,
    TypeInfo(TEnumOpenapipf69), nil, @ENUMOPENAPIPF69_TXT,
    TypeInfo(TEnumOpenapipf70), nil, @ENUMOPENAPIPF70_TXT,
    TypeInfo(TEnumOpenapipf71), nil, @ENUMOPENAPIPF71_TXT,
    TypeInfo(TEnumOpenapipf72), nil, @ENUMOPENAPIPF72_TXT,
    TypeInfo(TEnumOpenapipf73), nil, @ENUMOPENAPIPF73_TXT,
    TypeInfo(TEnumOpenapipf74), nil, @ENUMOPENAPIPF74_TXT,
    TypeInfo(TEnumOpenapipf75), nil, @ENUMOPENAPIPF75_TXT,
    TypeInfo(TEnumOpenapipf76), nil, @ENUMOPENAPIPF76_TXT,
    TypeInfo(TEnumOpenapipf77), nil, @ENUMOPENAPIPF77_TXT,
    TypeInfo(TEnumOpenapipf78), nil, @ENUMOPENAPIPF78_TXT,
    TypeInfo(TEnumOpenapipf79), nil, @ENUMOPENAPIPF79_TXT,
    TypeInfo(TEnumOpenapipf80), nil, @ENUMOPENAPIPF80_TXT,
    TypeInfo(TEnumOpenapipf81), nil, @ENUMOPENAPIPF81_TXT,
    TypeInfo(TEnumOpenapipf82), nil, @ENUMOPENAPIPF82_TXT,
    TypeInfo(TEnumOpenapipf83), nil, @ENUMOPENAPIPF83_TXT,
    TypeInfo(TEnumOpenapipf84), nil, @ENUMOPENAPIPF84_TXT,
    TypeInfo(TEnumOpenapipf85), nil, @ENUMOPENAPIPF85_TXT,
    TypeInfo(TEnumOpenapipf86), nil, @ENUMOPENAPIPF86_TXT,
    TypeInfo(TEnumOpenapipf87), nil, @ENUMOPENAPIPF87_TXT,
    TypeInfo(TEnumOpenapipf88), nil, @ENUMOPENAPIPF88_TXT,
    TypeInfo(TEnumOpenapipf89), nil, @ENUMOPENAPIPF89_TXT,
    TypeInfo(TEnumOpenapipf90), nil, @ENUMOPENAPIPF90_TXT,
    TypeInfo(TEnumOpenapipf91), nil, @ENUMOPENAPIPF91_TXT,
    TypeInfo(TEnumOpenapipf92), nil, @ENUMOPENAPIPF92_TXT,
    TypeInfo(TEnumOpenapipf93), nil, @ENUMOPENAPIPF93_TXT,
    TypeInfo(TEnumOpenapipf94), nil, @ENUMOPENAPIPF94_TXT,
    TypeInfo(TEnumOpenapipf95), nil, @ENUMOPENAPIPF95_TXT,
    TypeInfo(TEnumOpenapipf96), nil, @ENUMOPENAPIPF96_TXT,
    TypeInfo(TEnumOpenapipf97), nil, @ENUMOPENAPIPF97_TXT,
    TypeInfo(TEnumOpenapipf98), nil, @ENUMOPENAPIPF98_TXT,
    TypeInfo(TEnumOpenapipf99), nil, @ENUMOPENAPIPF99_TXT,
    TypeInfo(TEnumOpenapipf100), nil, @ENUMOPENAPIPF100_TXT,
    TypeInfo(TEnumOpenapipf101), nil, @ENUMOPENAPIPF101_TXT,
    TypeInfo(TEnumOpenapipf102), nil, @ENUMOPENAPIPF102_TXT,
    TypeInfo(TEnumOpenapipf103), nil, @ENUMOPENAPIPF103_TXT,
    TypeInfo(TEnumOpenapipf104), nil, @ENUMOPENAPIPF104_TXT,
    TypeInfo(TEnumOpenapipf105), nil, @ENUMOPENAPIPF105_TXT,
    TypeInfo(TEnumOpenapipf106), nil, @ENUMOPENAPIPF106_TXT,
    TypeInfo(TEnumOpenapipf107), nil, @ENUMOPENAPIPF107_TXT,
    TypeInfo(TEnumOpenapipf108), nil, @ENUMOPENAPIPF108_TXT,
    TypeInfo(TEnumOpenapipf109), nil, @ENUMOPENAPIPF109_TXT,
    TypeInfo(TEnumOpenapipf110), nil, @ENUMOPENAPIPF110_TXT,
    TypeInfo(TEnumOpenapipf111), nil, @ENUMOPENAPIPF111_TXT,
    TypeInfo(TEnumOpenapipf112), nil, @ENUMOPENAPIPF112_TXT,
    TypeInfo(TEnumOpenapipf113), nil, @ENUMOPENAPIPF113_TXT,
    TypeInfo(TEnumOpenapipf114), nil, @ENUMOPENAPIPF114_TXT,
    TypeInfo(TEnumOpenapipf115), nil, @ENUMOPENAPIPF115_TXT,
    TypeInfo(TEnumOpenapipf116), nil, @ENUMOPENAPIPF116_TXT,
    TypeInfo(TEnumOpenapipf117), nil, @ENUMOPENAPIPF117_TXT,
    TypeInfo(TEnumOpenapipf118), nil, @ENUMOPENAPIPF118_TXT,
    TypeInfo(TEnumOpenapipf119), nil, @ENUMOPENAPIPF119_TXT,
    TypeInfo(TEnumOpenapipf120), nil, @ENUMOPENAPIPF120_TXT]);
  Rtti.RegisterFromText([
    TypeInfo(TACMEAccountKey), _TACMEAccountKey,
    TypeInfo(TACMEAccountKeyRegister), _TACMEAccountKeyRegister,
    TypeInfo(TACMECertificate), _TACMECertificate,
    TypeInfo(TACMECertificateAction), _TACMECertificateAction,
    TypeInfo(TACMECertificateDomain), _TACMECertificateDomain,
    TypeInfo(TACMECertificateIssue), _TACMECertificateIssue,
    TypeInfo(TACMECertificateRenew), _TACMECertificateRenew,
    TypeInfo(TACMESettings), _TACMESettings,
    TypeInfo(TARPTable), _TARPTable,
    TypeInfo(TAuthServer), _TAuthServer,
    TypeInfo(TAuthenticationError), _TAuthenticationError,
    TypeInfo(TAvailableInterface), _TAvailableInterface,
    TypeInfo(TAvailablePackage), _TAvailablePackage,
    TypeInfo(TBINDAccessList), _TBINDAccessList,
    TypeInfo(TBINDAccessListEntry), _TBINDAccessListEntry,
    TypeInfo(TBINDSettings), _TBINDSettings,
    TypeInfo(TBINDSyncRemoteHost), _TBINDSyncRemoteHost,
    TypeInfo(TBINDSyncSettings), _TBINDSyncSettings,
    TypeInfo(TBINDView), _TBINDView,
    TypeInfo(TBINDZone), _TBINDZone,
    TypeInfo(TBINDZoneRecord), _TBINDZoneRecord,
    TypeInfo(TCARP), _TCARP,
    TypeInfo(TCertificate), _TCertificate,
    TypeInfo(TCertificateAuthority), _TCertificateAuthority,
    TypeInfo(TCertificateAuthorityGenerate), _TCertificateAuthorityGenerate,
    TypeInfo(TCertificateAuthorityRenew), _TCertificateAuthorityRenew,
    TypeInfo(TCertificateGenerate), _TCertificateGenerate,
    TypeInfo(TCertificatePKCS12Export), _TCertificatePKCS12Export,
    TypeInfo(TCertificateRenew), _TCertificateRenew,
    TypeInfo(TCertificateRevocationList), _TCertificateRevocationList,
    TypeInfo(TCertificateRevocationListRevokedCertificate), _TCertificateRevocationListRevokedCertificate,
    TypeInfo(TCertificateSigningRequest), _TCertificateSigningRequest,
    TypeInfo(TCertificateSigningRequestSign), _TCertificateSigningRequestSign,
    TypeInfo(TCommandPrompt), _TCommandPrompt,
    TypeInfo(TConfigHistoryRevision), _TConfigHistoryRevision,
    TypeInfo(TConflictError), _TConflictError,
    TypeInfo(TCronJob), _TCronJob,
    TypeInfo(TDHCPLog), _TDHCPLog,
    TypeInfo(TDHCPServer), _TDHCPServer,
    TypeInfo(TDHCPServerAddressPool), _TDHCPServerAddressPool,
    TypeInfo(TDHCPServerApply), _TDHCPServerApply,
    TypeInfo(TDHCPServerBackend), _TDHCPServerBackend,
    TypeInfo(TDHCPServerCustomOption), _TDHCPServerCustomOption,
    TypeInfo(TDHCPServerLease), _TDHCPServerLease,
    TypeInfo(TDHCPServerStaticMapping), _TDHCPServerStaticMapping,
    TypeInfo(TDNSForwarderApply), _TDNSForwarderApply,
    TypeInfo(TDNSForwarderHostOverride), _TDNSForwarderHostOverride,
    TypeInfo(TDNSForwarderHostOverrideAlias), _TDNSForwarderHostOverrideAlias,
    TypeInfo(TDNSResolverAccessList), _TDNSResolverAccessList,
    TypeInfo(TDNSResolverAccessListNetwork), _TDNSResolverAccessListNetwork,
    TypeInfo(TDNSResolverApply), _TDNSResolverApply,
    TypeInfo(TDNSResolverDomainOverride), _TDNSResolverDomainOverride,
    TypeInfo(TDNSResolverHostOverride), _TDNSResolverHostOverride,
    TypeInfo(TDNSResolverHostOverrideAlias), _TDNSResolverHostOverrideAlias,
    TypeInfo(TDNSResolverSettings), _TDNSResolverSettings,
    TypeInfo(TDefaultGateway), _TDefaultGateway,
    TypeInfo(TEmailNotificationSettings), _TEmailNotificationSettings,
    TypeInfo(TFailedDependencyError), _TFailedDependencyError,
    TypeInfo(TFirewallAdvancedSettings), _TFirewallAdvancedSettings,
    TypeInfo(TFirewallAlias), _TFirewallAlias,
    TypeInfo(TFirewallApply), _TFirewallApply,
    TypeInfo(TFirewallLog), _TFirewallLog,
    TypeInfo(TFirewallRule), _TFirewallRule,
    TypeInfo(TFirewallSchedule), _TFirewallSchedule,
    TypeInfo(TFirewallScheduleTimeRange), _TFirewallScheduleTimeRange,
    TypeInfo(TFirewallState), _TFirewallState,
    TypeInfo(TFirewallStatesSize), _TFirewallStatesSize,
    TypeInfo(TForbiddenError), _TForbiddenError,
    TypeInfo(TGraphQL), _TGraphQL,
    TypeInfo(TDtoOpenapipf2), _TDtoOpenapipf2,
    TypeInfo(TDtoOpenapipf3), _TDtoOpenapipf3,
    TypeInfo(TDtoOpenapipf1), _TDtoOpenapipf1,
    TypeInfo(TGraphQLResponse), _TGraphQLResponse,
    TypeInfo(THAProxyApply), _THAProxyApply,
    TypeInfo(THAProxyBackend), _THAProxyBackend,
    TypeInfo(THAProxyBackendACL), _THAProxyBackendACL,
    TypeInfo(THAProxyBackendAction), _THAProxyBackendAction,
    TypeInfo(THAProxyBackendErrorFile), _THAProxyBackendErrorFile,
    TypeInfo(THAProxyBackendServer), _THAProxyBackendServer,
    TypeInfo(THAProxyDNSResolver), _THAProxyDNSResolver,
    TypeInfo(THAProxyEmailMailer), _THAProxyEmailMailer,
    TypeInfo(THAProxyFile), _THAProxyFile,
    TypeInfo(THAProxyFrontend), _THAProxyFrontend,
    TypeInfo(THAProxyFrontendACL), _THAProxyFrontendACL,
    TypeInfo(THAProxyFrontendAction), _THAProxyFrontendAction,
    TypeInfo(THAProxyFrontendAddress), _THAProxyFrontendAddress,
    TypeInfo(THAProxyFrontendErrorFile), _THAProxyFrontendErrorFile,
    TypeInfo(THAProxySettings), _THAProxySettings,
    TypeInfo(TIPsecApply), _TIPsecApply,
    TypeInfo(TIPsecChildSAStatus), _TIPsecChildSAStatus,
    TypeInfo(TIPsecPhase1), _TIPsecPhase1,
    TypeInfo(TIPsecPhase1Encryption), _TIPsecPhase1Encryption,
    TypeInfo(TIPsecPhase2), _TIPsecPhase2,
    TypeInfo(TIPsecPhase2Encryption), _TIPsecPhase2Encryption,
    TypeInfo(TIPsecSAStatus), _TIPsecSAStatus,
    TypeInfo(TInterfaceApply), _TInterfaceApply,
    TypeInfo(TInterfaceBridge), _TInterfaceBridge,
    TypeInfo(TInterfaceGRE), _TInterfaceGRE,
    TypeInfo(TInterfaceGroup), _TInterfaceGroup,
    TypeInfo(TInterfaceLAGG), _TInterfaceLAGG,
    TypeInfo(TInterfaceStats), _TInterfaceStats,
    TypeInfo(TInterfaceVLAN), _TInterfaceVLAN,
    TypeInfo(TLogSettings), _TLogSettings,
    TypeInfo(TMediaTypeError), _TMediaTypeError,
    TypeInfo(TMethodNotAllowedError), _TMethodNotAllowedError,
    TypeInfo(TNTPSettings), _TNTPSettings,
    TypeInfo(TNTPTimeServer), _TNTPTimeServer,
    TypeInfo(TNetworkInterface), _TNetworkInterface,
    TypeInfo(TNotAcceptableError), _TNotAcceptableError,
    TypeInfo(TNotFoundError), _TNotFoundError,
    TypeInfo(TOneToOneNATMapping), _TOneToOneNATMapping,
    TypeInfo(TOpenVPNClient), _TOpenVPNClient,
    TypeInfo(TOpenVPNClientSpecificOverride), _TOpenVPNClientSpecificOverride,
    TypeInfo(TOpenVPNClientStatus), _TOpenVPNClientStatus,
    TypeInfo(TOpenVPNServer), _TOpenVPNServer,
    TypeInfo(TOpenVPNServerConnectionStatus), _TOpenVPNServerConnectionStatus,
    TypeInfo(TOpenVPNServerRouteStatus), _TOpenVPNServerRouteStatus,
    TypeInfo(TOpenVPNServerStatus), _TOpenVPNServerStatus,
    TypeInfo(TOutboundNATMapping), _TOutboundNATMapping,
    TypeInfo(TOutboundNATMode), _TOutboundNATMode,
    TypeInfo(TPackage), _TPackage,
    TypeInfo(TPortForward), _TPortForward,
    TypeInfo(TRESTAPIAccessListEntry), _TRESTAPIAccessListEntry,
    TypeInfo(TRESTAPIJWT), _TRESTAPIJWT,
    TypeInfo(TRESTAPIKey), _TRESTAPIKey,
    TypeInfo(TRESTAPISettings), _TRESTAPISettings,
    TypeInfo(TRESTAPISettingsSync), _TRESTAPISettingsSync,
    TypeInfo(TRESTAPIVersion), _TRESTAPIVersion,
    TypeInfo(TRoutingApply), _TRoutingApply,
    TypeInfo(TRoutingGateway), _TRoutingGateway,
    TypeInfo(TRoutingGatewayGroup), _TRoutingGatewayGroup,
    TypeInfo(TRoutingGatewayGroupPriority), _TRoutingGatewayGroupPriority,
    TypeInfo(TRoutingGatewayStatus), _TRoutingGatewayStatus,
    TypeInfo(TSSH), _TSSH,
    TypeInfo(TServerError), _TServerError,
    TypeInfo(TService), _TService,
    TypeInfo(TServiceUnavailableError), _TServiceUnavailableError,
    TypeInfo(TServiceWatchdog), _TServiceWatchdog,
    TypeInfo(TStaticRoute), _TStaticRoute,
    TypeInfo(TSuccess), _TSuccess,
    TypeInfo(TSystemConsole), _TSystemConsole,
    TypeInfo(TSystemDNS), _TSystemDNS,
    TypeInfo(TSystemHalt), _TSystemHalt,
    TypeInfo(TSystemHostname), _TSystemHostname,
    TypeInfo(TSystemLog), _TSystemLog,
    TypeInfo(TSystemReboot), _TSystemReboot,
    TypeInfo(TSystemStatus), _TSystemStatus,
    TypeInfo(TSystemTunable), _TSystemTunable,
    TypeInfo(TSystemVersion), _TSystemVersion,
    TypeInfo(TTrafficShaper), _TTrafficShaper,
    TypeInfo(TTrafficShaperLimiter), _TTrafficShaperLimiter,
    TypeInfo(TTrafficShaperLimiterBandwidth), _TTrafficShaperLimiterBandwidth,
    TypeInfo(TTrafficShaperLimiterQueue), _TTrafficShaperLimiterQueue,
    TypeInfo(TTrafficShaperQueue), _TTrafficShaperQueue,
    TypeInfo(TUnprocessableContentError), _TUnprocessableContentError,
    TypeInfo(TUser), _TUser,
    TypeInfo(TUserGroup), _TUserGroup,
    TypeInfo(TVirtualIP), _TVirtualIP,
    TypeInfo(TVirtualIPApply), _TVirtualIPApply,
    TypeInfo(TWakeOnLANSend), _TWakeOnLANSend,
    TypeInfo(TWebGUISettings), _TWebGUISettings,
    TypeInfo(TWireGuardApply), _TWireGuardApply,
    TypeInfo(TWireGuardPeer), _TWireGuardPeer,
    TypeInfo(TWireGuardPeerAllowedIP), _TWireGuardPeerAllowedIP,
    TypeInfo(TWireGuardSettings), _TWireGuardSettings,
    TypeInfo(TWireGuardTunnel), _TWireGuardTunnel,
    TypeInfo(TWireGuardTunnelAddress), _TWireGuardTunnelAddress]);
end;

initialization
  RegisterRtti;

end.
