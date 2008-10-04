# Autogenerated file. DO NOT EDIT
        
package Crypt::NSS::Constants;

require Exporter;

our @ISA = qw(Exporter);

our @EXPORT = qw();

our @EXPORT_OK = qw(
	SSL_ALLOWED
	SSL_AT_MD5_WITH_RSA_ENCRYPTION
	SSL_BYPASS_PKCS11
	SSL_CBP_SSL3
	SSL_CBP_TLS1_0
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5
	SSL_CK_DES_64_CBC_WITH_MD5
	SSL_CK_IDEA_128_CBC_WITH_MD5
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
	SSL_CK_RC2_128_CBC_WITH_MD5
	SSL_CK_RC4_128_EXPORT40_WITH_MD5
	SSL_CK_RC4_128_WITH_MD5
	SSL_CT_X509_CERTIFICATE
	SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
	SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA
	SSL_DHE_DSS_WITH_DES_CBC_SHA
	SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
	SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
	SSL_DHE_RSA_WITH_DES_CBC_SHA
	SSL_DH_ANON_EXPORT_WITH_DES40_CBC_SHA
	SSL_DH_ANON_EXPORT_WITH_RC4_40_MD5
	SSL_DH_ANON_WITH_3DES_EDE_CBC_SHA
	SSL_DH_ANON_WITH_DES_CBC_SHA
	SSL_DH_ANON_WITH_RC4_128_MD5
	SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
	SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA
	SSL_DH_DSS_WITH_DES_CBC_SHA
	SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
	SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA
	SSL_DH_RSA_WITH_DES_CBC_SHA
	SSL_ENABLE_FDX
	SSL_ENABLE_SESSION_TICKETS
	SSL_ENABLE_SSL2
	SSL_ENABLE_SSL3
	SSL_ENABLE_TLS
	SSL_EN_DES_192_EDE3_CBC_WITH_MD5
	SSL_EN_DES_64_CBC_WITH_MD5
	SSL_EN_IDEA_128_CBC_WITH_MD5
	SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5
	SSL_EN_RC2_128_CBC_WITH_MD5
	SSL_EN_RC4_128_EXPORT40_WITH_MD5
	SSL_EN_RC4_128_WITH_MD5
	SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA
	SSL_FORTEZZA_DMS_WITH_NULL_SHA
	SSL_FORTEZZA_DMS_WITH_RC4_128_SHA
	SSL_HANDSHAKE_AS_CLIENT
	SSL_HANDSHAKE_AS_SERVER
	SSL_HL_CLIENT_CERTIFICATE_HBYTES
	SSL_HL_CLIENT_FINISHED_HBYTES
	SSL_HL_CLIENT_HELLO_HBYTES
	SSL_HL_CLIENT_MASTER_KEY_HBYTES
	SSL_HL_ERROR_HBYTES
	SSL_HL_REQUEST_CERTIFICATE_HBYTES
	SSL_HL_SERVER_FINISHED_HBYTES
	SSL_HL_SERVER_HELLO_HBYTES
	SSL_HL_SERVER_VERIFY_HBYTES
	SSL_LIBRARY_VERSION_2
	SSL_LIBRARY_VERSION_3_0
	SSL_LIBRARY_VERSION_3_1_TLS
	SSL_MT_CLIENT_CERTIFICATE
	SSL_MT_CLIENT_FINISHED
	SSL_MT_CLIENT_HELLO
	SSL_MT_CLIENT_MASTER_KEY
	SSL_MT_ERROR
	SSL_MT_REQUEST_CERTIFICATE
	SSL_MT_SERVER_FINISHED
	SSL_MT_SERVER_HELLO
	SSL_MT_SERVER_VERIFY
	SSL_NOT_ALLOWED
	SSL_NO_CACHE
	SSL_NO_LOCKS
	SSL_NO_STEP_DOWN
	SSL_NULL_WITH_NULL_NULL
	SSL_OPTION_DISABLED
	SSL_OPTION_ENABLED
	SSL_PE_BAD_CERTIFICATE
	SSL_PE_NO_CERTIFICATE
	SSL_PE_NO_CYPHERS
	SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE
	SSL_PKCS6_CERTIFICATE
	SSL_REQUEST_CERTIFICATE
	SSL_REQUIRE_ALWAYS
	SSL_REQUIRE_CERTIFICATE
	SSL_REQUIRE_FIRST_HANDSHAKE
	SSL_REQUIRE_NEVER
	SSL_REQUIRE_NO_ERROR
	SSL_RESTRICTED
	SSL_ROLLBACK_DETECTION
	SSL_RSA_EXPORT_WITH_DES40_CBC_SHA
	SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5
	SSL_RSA_EXPORT_WITH_RC4_40_MD5
	SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
	SSL_RSA_FIPS_WITH_DES_CBC_SHA
	SSL_RSA_OLDFIPS_WITH_3DES_EDE_CBC_SHA
	SSL_RSA_OLDFIPS_WITH_DES_CBC_SHA
	SSL_RSA_WITH_3DES_EDE_CBC_SHA
	SSL_RSA_WITH_DES_CBC_SHA
	SSL_RSA_WITH_IDEA_CBC_SHA
	SSL_RSA_WITH_NULL_MD5
	SSL_RSA_WITH_NULL_SHA
	SSL_RSA_WITH_RC4_128_MD5
	SSL_RSA_WITH_RC4_128_SHA
	SSL_SECURITY
	SSL_SECURITY_STATUS_FORTEZZA
	SSL_SECURITY_STATUS_OFF
	SSL_SECURITY_STATUS_ON_HIGH
	SSL_SECURITY_STATUS_ON_LOW
	SSL_SOCKS
	SSL_V2_COMPATIBLE_HELLO
	TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
	TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
	TLS_DHE_DSS_WITH_RC4_128_SHA
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
	TLS_DH_ANON_WITH_AES_128_CBC_SHA
	TLS_DH_ANON_WITH_AES_256_CBC_SHA
	TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA
	TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA
	TLS_DH_DSS_WITH_AES_128_CBC_SHA
	TLS_DH_DSS_WITH_AES_256_CBC_SHA
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
	TLS_DH_RSA_WITH_AES_128_CBC_SHA
	TLS_DH_RSA_WITH_AES_256_CBC_SHA
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	TLS_ECDHE_ECDSA_WITH_NULL_SHA
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	TLS_ECDHE_RSA_WITH_NULL_SHA
	TLS_ECDHE_RSA_WITH_RC4_128_SHA
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
	TLS_ECDH_ECDSA_WITH_NULL_SHA
	TLS_ECDH_ECDSA_WITH_RC4_128_SHA
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
	TLS_ECDH_RSA_WITH_NULL_SHA
	TLS_ECDH_RSA_WITH_RC4_128_SHA
	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
	TLS_ECDH_anon_WITH_AES_128_CBC_SHA
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA
	TLS_ECDH_anon_WITH_NULL_SHA
	TLS_ECDH_anon_WITH_RC4_128_SHA
	TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
	TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
	TLS_RSA_WITH_AES_128_CBC_SHA
	TLS_RSA_WITH_AES_256_CBC_SHA
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
);

our %EXPORT_TAGS = (
	ssl => [qw(
		SSL_ALLOWED
		SSL_AT_MD5_WITH_RSA_ENCRYPTION
		SSL_BYPASS_PKCS11
		SSL_CBP_SSL3
		SSL_CBP_TLS1_0
		SSL_CK_DES_192_EDE3_CBC_WITH_MD5
		SSL_CK_DES_64_CBC_WITH_MD5
		SSL_CK_IDEA_128_CBC_WITH_MD5
		SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
		SSL_CK_RC2_128_CBC_WITH_MD5
		SSL_CK_RC4_128_EXPORT40_WITH_MD5
		SSL_CK_RC4_128_WITH_MD5
		SSL_CT_X509_CERTIFICATE
		SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
		SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA
		SSL_DHE_DSS_WITH_DES_CBC_SHA
		SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
		SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA
		SSL_DHE_RSA_WITH_DES_CBC_SHA
		SSL_DH_ANON_EXPORT_WITH_DES40_CBC_SHA
		SSL_DH_ANON_EXPORT_WITH_RC4_40_MD5
		SSL_DH_ANON_WITH_3DES_EDE_CBC_SHA
		SSL_DH_ANON_WITH_DES_CBC_SHA
		SSL_DH_ANON_WITH_RC4_128_MD5
		SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
		SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA
		SSL_DH_DSS_WITH_DES_CBC_SHA
		SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
		SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA
		SSL_DH_RSA_WITH_DES_CBC_SHA
		SSL_ENABLE_FDX
		SSL_ENABLE_SESSION_TICKETS
		SSL_ENABLE_SSL2
		SSL_ENABLE_SSL3
		SSL_ENABLE_TLS
		SSL_EN_DES_192_EDE3_CBC_WITH_MD5
		SSL_EN_DES_64_CBC_WITH_MD5
		SSL_EN_IDEA_128_CBC_WITH_MD5
		SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5
		SSL_EN_RC2_128_CBC_WITH_MD5
		SSL_EN_RC4_128_EXPORT40_WITH_MD5
		SSL_EN_RC4_128_WITH_MD5
		SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA
		SSL_FORTEZZA_DMS_WITH_NULL_SHA
		SSL_FORTEZZA_DMS_WITH_RC4_128_SHA
		SSL_HANDSHAKE_AS_CLIENT
		SSL_HANDSHAKE_AS_SERVER
		SSL_HL_CLIENT_CERTIFICATE_HBYTES
		SSL_HL_CLIENT_FINISHED_HBYTES
		SSL_HL_CLIENT_HELLO_HBYTES
		SSL_HL_CLIENT_MASTER_KEY_HBYTES
		SSL_HL_ERROR_HBYTES
		SSL_HL_REQUEST_CERTIFICATE_HBYTES
		SSL_HL_SERVER_FINISHED_HBYTES
		SSL_HL_SERVER_HELLO_HBYTES
		SSL_HL_SERVER_VERIFY_HBYTES
		SSL_LIBRARY_VERSION_2
		SSL_LIBRARY_VERSION_3_0
		SSL_LIBRARY_VERSION_3_1_TLS
		SSL_MT_CLIENT_CERTIFICATE
		SSL_MT_CLIENT_FINISHED
		SSL_MT_CLIENT_HELLO
		SSL_MT_CLIENT_MASTER_KEY
		SSL_MT_ERROR
		SSL_MT_REQUEST_CERTIFICATE
		SSL_MT_SERVER_FINISHED
		SSL_MT_SERVER_HELLO
		SSL_MT_SERVER_VERIFY
		SSL_NOT_ALLOWED
		SSL_NO_CACHE
		SSL_NO_LOCKS
		SSL_NO_STEP_DOWN
		SSL_NULL_WITH_NULL_NULL
		SSL_OPTION_DISABLED
		SSL_OPTION_ENABLED
		SSL_PE_BAD_CERTIFICATE
		SSL_PE_NO_CERTIFICATE
		SSL_PE_NO_CYPHERS
		SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE
		SSL_PKCS6_CERTIFICATE
		SSL_REQUEST_CERTIFICATE
		SSL_REQUIRE_ALWAYS
		SSL_REQUIRE_CERTIFICATE
		SSL_REQUIRE_FIRST_HANDSHAKE
		SSL_REQUIRE_NEVER
		SSL_REQUIRE_NO_ERROR
		SSL_RESTRICTED
		SSL_ROLLBACK_DETECTION
		SSL_RSA_EXPORT_WITH_DES40_CBC_SHA
		SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5
		SSL_RSA_EXPORT_WITH_RC4_40_MD5
		SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
		SSL_RSA_FIPS_WITH_DES_CBC_SHA
		SSL_RSA_OLDFIPS_WITH_3DES_EDE_CBC_SHA
		SSL_RSA_OLDFIPS_WITH_DES_CBC_SHA
		SSL_RSA_WITH_3DES_EDE_CBC_SHA
		SSL_RSA_WITH_DES_CBC_SHA
		SSL_RSA_WITH_IDEA_CBC_SHA
		SSL_RSA_WITH_NULL_MD5
		SSL_RSA_WITH_NULL_SHA
		SSL_RSA_WITH_RC4_128_MD5
		SSL_RSA_WITH_RC4_128_SHA
		SSL_SECURITY
		SSL_SECURITY_STATUS_FORTEZZA
		SSL_SECURITY_STATUS_OFF
		SSL_SECURITY_STATUS_ON_HIGH
		SSL_SECURITY_STATUS_ON_LOW
		SSL_SOCKS
		SSL_V2_COMPATIBLE_HELLO
		TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
		TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA
		TLS_DHE_DSS_WITH_AES_128_CBC_SHA
		TLS_DHE_DSS_WITH_AES_256_CBC_SHA
		TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
		TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
		TLS_DHE_DSS_WITH_RC4_128_SHA
		TLS_DHE_RSA_WITH_AES_128_CBC_SHA
		TLS_DHE_RSA_WITH_AES_256_CBC_SHA
		TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
		TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
		TLS_DH_ANON_WITH_AES_128_CBC_SHA
		TLS_DH_ANON_WITH_AES_256_CBC_SHA
		TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA
		TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA
		TLS_DH_DSS_WITH_AES_128_CBC_SHA
		TLS_DH_DSS_WITH_AES_256_CBC_SHA
		TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
		TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
		TLS_DH_RSA_WITH_AES_128_CBC_SHA
		TLS_DH_RSA_WITH_AES_256_CBC_SHA
		TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
		TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
		TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
		TLS_ECDHE_ECDSA_WITH_NULL_SHA
		TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
		TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
		TLS_ECDHE_RSA_WITH_NULL_SHA
		TLS_ECDHE_RSA_WITH_RC4_128_SHA
		TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
		TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
		TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
		TLS_ECDH_ECDSA_WITH_NULL_SHA
		TLS_ECDH_ECDSA_WITH_RC4_128_SHA
		TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
		TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
		TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
		TLS_ECDH_RSA_WITH_NULL_SHA
		TLS_ECDH_RSA_WITH_RC4_128_SHA
		TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA
		TLS_ECDH_anon_WITH_AES_128_CBC_SHA
		TLS_ECDH_anon_WITH_AES_256_CBC_SHA
		TLS_ECDH_anon_WITH_NULL_SHA
		TLS_ECDH_anon_WITH_RC4_128_SHA
		TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
		TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
		TLS_RSA_WITH_AES_128_CBC_SHA
		TLS_RSA_WITH_AES_256_CBC_SHA
		TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
		TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
	)],
);

use constant {
	SSL_ALLOWED => 1,	# 
	SSL_AT_MD5_WITH_RSA_ENCRYPTION => 0x01,	# 
	SSL_BYPASS_PKCS11 => 16,	# use PKCS#11 for pub key only
	SSL_CBP_SSL3 => 0x0001,	# test SSL v3 mechanisms
	SSL_CBP_TLS1_0 => 0x0002,	# test TLS v1.0 mechanisms
	SSL_CK_DES_192_EDE3_CBC_WITH_MD5 => 0x07,	# 
	SSL_CK_DES_64_CBC_WITH_MD5 => 0x06,	# 
	SSL_CK_IDEA_128_CBC_WITH_MD5 => 0x05,	# 
	SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 => 0x04,	# 
	SSL_CK_RC2_128_CBC_WITH_MD5 => 0x03,	# 
	SSL_CK_RC4_128_EXPORT40_WITH_MD5 => 0x02,	# 
	SSL_CK_RC4_128_WITH_MD5 => 0x01,	# 
	SSL_CT_X509_CERTIFICATE => 0x01,	# 
	SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA => 0x0011,	# 
	SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA => 0x0013,	# 
	SSL_DHE_DSS_WITH_DES_CBC_SHA => 0x0012,	# 
	SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x0014,	# 
	SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA => 0x0016,	# 
	SSL_DHE_RSA_WITH_DES_CBC_SHA => 0x0015,	# 
	SSL_DH_ANON_EXPORT_WITH_DES40_CBC_SHA => 0x0019,	# 
	SSL_DH_ANON_EXPORT_WITH_RC4_40_MD5 => 0x0017,	# 
	SSL_DH_ANON_WITH_3DES_EDE_CBC_SHA => 0x001b,	# 
	SSL_DH_ANON_WITH_DES_CBC_SHA => 0x001a,	# 
	SSL_DH_ANON_WITH_RC4_128_MD5 => 0x0018,	# 
	SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA => 0x000b,	# 
	SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA => 0x000d,	# 
	SSL_DH_DSS_WITH_DES_CBC_SHA => 0x000c,	# 
	SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x000e,	# 
	SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA => 0x0010,	# 
	SSL_DH_RSA_WITH_DES_CBC_SHA => 0x000f,	# 
	SSL_ENABLE_FDX => 11,	# permit simultaneous read/write
	SSL_ENABLE_SESSION_TICKETS => 18,	# Enable TLS SessionTicket
	SSL_ENABLE_SSL2 => 7,	# enable ssl v2 (on by default)
	SSL_ENABLE_SSL3 => 8,	# enable ssl v3 (on by default)
	SSL_ENABLE_TLS => 13,	# enable TLS (on by default)
	SSL_EN_DES_192_EDE3_CBC_WITH_MD5 => 0xFF07,	# 
	SSL_EN_DES_64_CBC_WITH_MD5 => 0xFF06,	# 
	SSL_EN_IDEA_128_CBC_WITH_MD5 => 0xFF05,	# 
	SSL_EN_RC2_128_CBC_EXPORT40_WITH_MD5 => 0xFF04,	# 
	SSL_EN_RC2_128_CBC_WITH_MD5 => 0xFF03,	# 
	SSL_EN_RC4_128_EXPORT40_WITH_MD5 => 0xFF02,	# 
	SSL_EN_RC4_128_WITH_MD5 => 0xFF01,	# 
	SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA => 0x001d,	# deprecated
	SSL_FORTEZZA_DMS_WITH_NULL_SHA => 0x001c,	# deprecated
	SSL_FORTEZZA_DMS_WITH_RC4_128_SHA => 0x001e,	# deprecated
	SSL_HANDSHAKE_AS_CLIENT => 5,	# force accept to hs as client
	SSL_HANDSHAKE_AS_SERVER => 6,	# force connect to hs as server
	SSL_HL_CLIENT_CERTIFICATE_HBYTES => 6,	# 
	SSL_HL_CLIENT_FINISHED_HBYTES => 1,	# 
	SSL_HL_CLIENT_HELLO_HBYTES => 9,	# 
	SSL_HL_CLIENT_MASTER_KEY_HBYTES => 10,	# 
	SSL_HL_ERROR_HBYTES => 3,	# 
	SSL_HL_REQUEST_CERTIFICATE_HBYTES => 2,	# 
	SSL_HL_SERVER_FINISHED_HBYTES => 1,	# 
	SSL_HL_SERVER_HELLO_HBYTES => 11,	# 
	SSL_HL_SERVER_VERIFY_HBYTES => 1,	# 
	SSL_LIBRARY_VERSION_2 => 0x0002,	# 
	SSL_LIBRARY_VERSION_3_0 => 0x0300,	# 
	SSL_LIBRARY_VERSION_3_1_TLS => 0x0301,	# 
	SSL_MT_CLIENT_CERTIFICATE => 8,	# 
	SSL_MT_CLIENT_FINISHED => 3,	# 
	SSL_MT_CLIENT_HELLO => 1,	# 
	SSL_MT_CLIENT_MASTER_KEY => 2,	# 
	SSL_MT_ERROR => 0,	# 
	SSL_MT_REQUEST_CERTIFICATE => 7,	# 
	SSL_MT_SERVER_FINISHED => 6,	# 
	SSL_MT_SERVER_HELLO => 4,	# 
	SSL_MT_SERVER_VERIFY => 5,	# 
	SSL_NOT_ALLOWED => 0,	# or invalid or unimplemented
	SSL_NO_CACHE => 9,	# don't use the session cache
	SSL_NO_LOCKS => 17,	# Don't use locks for protection
	SSL_NO_STEP_DOWN => 15,	# Disable export cipher suites
	SSL_NULL_WITH_NULL_NULL => 0x0000,	# 
	SSL_OPTION_DISABLED => 2,	# Disables an option
	SSL_OPTION_ENABLED => 1,	# Enables an option
	SSL_PE_BAD_CERTIFICATE => 0x0004,	# 
	SSL_PE_NO_CERTIFICATE => 0x0002,	# 
	SSL_PE_NO_CYPHERS => 0x0001,	# 
	SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE => 0x0006,	# 
	SSL_PKCS6_CERTIFICATE => 0x02,	# 
	SSL_REQUEST_CERTIFICATE => 3,	# (off by default)
	SSL_REQUIRE_ALWAYS => 1,	# 
	SSL_REQUIRE_CERTIFICATE => 10,	# (SSL_REQUIRE_FIRST_HANDSHAKE
	SSL_REQUIRE_FIRST_HANDSHAKE => 2,	# 
	SSL_REQUIRE_NEVER => 0,	# 
	SSL_REQUIRE_NO_ERROR => 3,	# 
	SSL_RESTRICTED => 2,	# only with "Step-Up" certs.
	SSL_ROLLBACK_DETECTION => 14,	# for compatibility, default: on
	SSL_RSA_EXPORT_WITH_DES40_CBC_SHA => 0x0008,	# 
	SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5 => 0x0006,	# 
	SSL_RSA_EXPORT_WITH_RC4_40_MD5 => 0x0003,	# 
	SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA => 0xfeff,	# 
	SSL_RSA_FIPS_WITH_DES_CBC_SHA => 0xfefe,	# 
	SSL_RSA_OLDFIPS_WITH_3DES_EDE_CBC_SHA => 0xffe0,	# 
	SSL_RSA_OLDFIPS_WITH_DES_CBC_SHA => 0xffe1,	# 
	SSL_RSA_WITH_3DES_EDE_CBC_SHA => 0x000a,	# 
	SSL_RSA_WITH_DES_CBC_SHA => 0x0009,	# 
	SSL_RSA_WITH_IDEA_CBC_SHA => 0x0007,	# 
	SSL_RSA_WITH_NULL_MD5 => 0x0001,	# 
	SSL_RSA_WITH_NULL_SHA => 0x0002,	# 
	SSL_RSA_WITH_RC4_128_MD5 => 0x0004,	# 
	SSL_RSA_WITH_RC4_128_SHA => 0x0005,	# 
	SSL_SECURITY => 1,	# (on by default)
	SSL_SECURITY_STATUS_FORTEZZA => 3,	# NO LONGER SUPPORTED
	SSL_SECURITY_STATUS_OFF => 0,	# 
	SSL_SECURITY_STATUS_ON_HIGH => 1,	# 
	SSL_SECURITY_STATUS_ON_LOW => 2,	# 
	SSL_SOCKS => 2,	# (off by default)
	SSL_V2_COMPATIBLE_HELLO => 12,	# send v3 client hello in v2 fmt
	TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA => 0x0063,	# 
	TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA => 0x0065,	# 
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA => 0x0032,	# 
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA => 0x0038,	# 
	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA => 0x0044,	# 
	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA => 0x0087,	# 
	TLS_DHE_DSS_WITH_RC4_128_SHA => 0x0066,	# 
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA => 0x0033,	# 
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA => 0x0039,	# 
	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0045,	# 
	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0088,	# 
	TLS_DH_ANON_WITH_AES_128_CBC_SHA => 0x0034,	# 
	TLS_DH_ANON_WITH_AES_256_CBC_SHA => 0x003A,	# 
	TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA => 0x0046,	# 
	TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA => 0x0089,	# 
	TLS_DH_DSS_WITH_AES_128_CBC_SHA => 0x0030,	# 
	TLS_DH_DSS_WITH_AES_256_CBC_SHA => 0x0036,	# 
	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA => 0x0042,	# 
	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA => 0x0085,	# 
	TLS_DH_RSA_WITH_AES_128_CBC_SHA => 0x0031,	# 
	TLS_DH_RSA_WITH_AES_256_CBC_SHA => 0x0037,	# 
	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0043,	# 
	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0086,	# 
	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xC008,	# 
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => 0xC009,	# 
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => 0xC00A,	# 
	TLS_ECDHE_ECDSA_WITH_NULL_SHA => 0xC006,	# 
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA => 0xC007,	# 
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => 0xC012,	# 
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => 0xC013,	# 
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => 0xC014,	# 
	TLS_ECDHE_RSA_WITH_NULL_SHA => 0xC010,	# 
	TLS_ECDHE_RSA_WITH_RC4_128_SHA => 0xC011,	# 
	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA => 0xC003,	# 
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA => 0xC004,	# 
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA => 0xC005,	# 
	TLS_ECDH_ECDSA_WITH_NULL_SHA => 0xC001,	# 
	TLS_ECDH_ECDSA_WITH_RC4_128_SHA => 0xC002,	# 
	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA => 0xC00D,	# 
	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA => 0xC00E,	# 
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA => 0xC00F,	# 
	TLS_ECDH_RSA_WITH_NULL_SHA => 0xC00B,	# 
	TLS_ECDH_RSA_WITH_RC4_128_SHA => 0xC00C,	# 
	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA => 0xC017,	# 
	TLS_ECDH_anon_WITH_AES_128_CBC_SHA => 0xC018,	# 
	TLS_ECDH_anon_WITH_AES_256_CBC_SHA => 0xC019,	# 
	TLS_ECDH_anon_WITH_NULL_SHA => 0xC015,	# 
	TLS_ECDH_anon_WITH_RC4_128_SHA => 0xC016,	# 
	TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA => 0x0062,	# 
	TLS_RSA_EXPORT1024_WITH_RC4_56_SHA => 0x0064,	# 
	TLS_RSA_WITH_AES_128_CBC_SHA => 0x002F,	# 
	TLS_RSA_WITH_AES_256_CBC_SHA => 0x0035,	# 
	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA => 0x0041,	# 
	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA => 0x0084,	# 
};

1;
__END__

=head1 NAME

Crypt::NSS::Constants - Constants used by NSS

=cut
