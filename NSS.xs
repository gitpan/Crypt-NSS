#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "nss.h"
#include "ssl.h"
#include "prio.h"
#include "prtypes.h"
#include "prnetdb.h"
#include "cert.h"

#include "ppport.h"

#define HAS_ARGUMENT(hv, key) hv_exists(hv, key, strlen(key))
#define SET_SOCKET_OPTION(socket, option, report) if (PR_SetSocketOption(socket, &option) != SECSuccess) { \
    PR_Close(socket); \
    throw_exception_from_nspr_error(report); \
}

#define EVALUATE_SEC_CALL(call, report) if (call != SECSuccess) { \
    throw_exception_from_nspr_error(report); \
}

#define EVALUATE_PR_CALL(call, report) if (call != PR_SUCCESS) { \
    throw_exception_from_nspr_error(report); \
}

struct NSS_SSL_Socket {
    PRFileDesc * fd;
    SV * pkcs11arg;
    PRNetAddr addr;
    bool connected;
};

typedef struct NSS_SSL_Socket NSS_SSL_Socket;

typedef CERTCertificate * Crypt__NSS__Certificate;

typedef NSS_SSL_Socket * Net__NSS__SSL;

//extern  PRInt16 SSL_NumImplementedCiphers;
//extern const PRInt16 SSL_ImplementedCiphers[];

static const char * config_dir = NULL;

static SV * PasswordFunc = NULL;

char *
pkcs11_password_func(PK11SlotInfo *info, PRBool retry, void *arg) {
    dSP;
    char * password, * tmp;
    I32 rcount;
    
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);

    XPUSHs(boolSV(retry));
    XPUSHs((SV *) arg);

    PUTBACK;

    rcount = call_sv(PasswordFunc, G_SCALAR);

    SPAGAIN;

    if (rcount == 1) {
        tmp = SvPV_nolen(POPs);
        Safefree(tmp);
        password = PORT_Strdup((char *) tmp);
    }

    PUTBACK;
    FREETMPS;
    LEAVE;

    return password;
}

static void
throw_exception_from_nspr_error(const char * desc) {
    PRInt32 len;
    char * tmpbuff;
    
    if ((len = PR_GetErrorTextLength())) {
        Newz(1, tmpbuff, len + 1, char);
        PR_GetErrorText(tmpbuff);
        croak("%s: %s (%d)", desc, tmpbuff, PR_GetError());
    }
    else {
        croak("%s: %d", desc, PR_GetError());
    }
}

static IV
get_argument_as_IV(HV *args, const char *key, IV default_value) {
    SV **value;

    value = hv_fetch(args, key, strlen(key), 0);
    
    if (value == NULL) {
        /* Failed to get key, return default */
        return default_value;
    }
    
    return SvIV(*value);
}

static PRBool
get_argument_as_PRBool(HV *args, const char *key, PRBool default_value) {
    SV **value;

    value = hv_fetch(args, key, strlen(key), 0);
    
    if (value == NULL) {
        /* Failed to get key, return default */
        return default_value;
    }
    
    return (PRBool) SvTRUE(*value);
}

MODULE = Crypt::NSS        PACKAGE = Net::NSS::SSL

Net::NSS::SSL
create_socket(pkg, type)
    const char * pkg;
    const char * type;
    PREINIT:
        NSS_SSL_Socket * socket;
    CODE:
        Newz(1, socket, 1, NSS_SSL_Socket);
        if (strEQ(type, "tcp")) {
            socket->fd = PR_NewTCPSocket();
        }
        else if (strEQ(type, "udp")) {
            socket->fd = PR_NewUDPSocket();
        }
        else {
            croak("Unknown socket type '%s'. Valid types are are 'tcp' and 'udp'", type);
        }
        
        if (socket->fd == NULL) {
            throw_exception_from_nspr_error("Failed to create new TCP socket");
        }        

        socket->connected = FALSE;
        RETVAL = socket;
    OUTPUT:
        RETVAL

void
set_socket_option(self, option, value)
    Net::NSS::SSL self;
    const char * option;
    I32 value;
    PREINIT:
        PRSocketOptionData socketOption;
    CODE: {
        if (strEQ(option, "KeepAlive")) {
            socketOption.option = PR_SockOpt_Keepalive;
            socketOption.value.keep_alive = value ? PR_TRUE : PR_FALSE;
        }
        else if (strEQ(option, "NoDelay")) {
            socketOption.option = PR_SockOpt_NoDelay;
            socketOption.value.no_delay = value ? PR_TRUE : PR_FALSE;
        }
        else if (strEQ(option, "Blocking")) {
            socketOption.option = PR_SockOpt_NoDelay;
            socketOption.value.non_blocking = value ? PR_FALSE : PR_TRUE;
        }
        else {
            croak("Unknown option '%s'", option);
        
        SET_SOCKET_OPTION(self->fd, socketOption, form("Failed to set option '%s' on socket", option));
    }

void
set_pkcs11_pin_arg(self, arg)
    Net::NSS::SSL self;
    SV * arg;
    CODE:
        if (self->pkcs11arg != NULL) {
            SvREFCNT_dec(self->pkcs11arg);
        }
        self->pkcs11arg = SvREFCNT_inc(arg);
        
void
set_domain(self, hostname)
    Net::NSS::SSL self;
    const char * hostname;
    CODE:
        EVALUATE_SEC_CALL(SSL_SetURL(self->fd, hostname), "Failed to set url")
    
void
connect(self, hostname, port, timeout = PR_INTERVAL_NO_TIMEOUT)
    Net::NSS::SSL self;
    const char * hostname;
    I32 port;
    I32 timeout;
    PREINIT:
        PRNetAddr addr;
        PRHostEnt hostentry;
        char buffer[PR_NETDB_BUF_SIZE];
    CODE:
        EVALUATE_PR_CALL(PR_GetHostByName(hostname, buffer, sizeof(buffer), &hostentry), "Can't lookup host")
        if (PR_EnumerateHostEnt(0, &hostentry, port, &addr) < 0) {
            throw_exception_from_nspr_error("Failed to get IP from host entry");
        }
        EVALUATE_PR_CALL(PR_Connect(self->fd, &addr, PR_INTERVAL_NO_TIMEOUT), "Connection failed")
        self->connected = boolSV(TRUE);
        
void
bind(self, hostname, port)
    Net::NSS::SSL self;
    const char * hostname;
    I32 port;
    PREINIT:
        PRNetAddr addr;
        PRHostEnt hostentry;
        char buffer[PR_NETDB_BUF_SIZE];
    CODE:
        if (hostname != NULL) {
            EVALUATE_PR_CALL(PR_GetHostByName(hostname, buffer, sizeof(buffer), &hostentry), "Can't lookup host")
            if (PR_EnumerateHostEnt(0, &hostentry, port, &addr) < 0) {
                throw_exception_from_nspr_error("Failed to get IP from host entry");
            }
        }
        else {
            addr.inet.family = PR_AF_INET;
            addr.inet.ip = PR_htonl(PR_INADDR_ANY);
            addr.inet.port = port;
        }
        EVALUATE_PR_CALL(PR_Bind(self->fd, &addr), "Connection failed")

Net::NSS::SSL
accept(self, timeout = PR_INTERVAL_NO_TIMEOUT)
    Net::NSS::SSL self
    I32 timeout;
    PREINIT:
        NSS_SSL_Socket * new_socket;
        PRNetAddr addr;
        PRFileDesc * remote_fd = NULL;
    CODE:
        remote_fd = PR_Accept(self->fd, &addr, timeout);
        if (remote_fd == NULL) {
            throw_exception_from_nspr_error("Accept failed");
        }
        Newz(1, new_socket, 1, NSS_SSL_Socket);
        new_socket->fd = remote_fd;
        Copy(&addr, &(new_socket->addr), 1, PRNetAddr);
        new_socket->connected = PR_TRUE;
        RETVAL = new_socket;
    OUTPUT:
        RETVAL
        
void
listen(self, queue_length=10)
    Net::NSS::SSL self;
    I32 queue_length;
    CODE:
        EVALUATE_PR_CALL(PR_Listen(self->fd, queue_length), "Listen failed")

void
import_into_ssl_layer(self, proto=NULL)
    Net::NSS::SSL self;
    Net::NSS::SSL proto;
    PREINIT:
        PRFileDesc * proto_sock = NULL;
    CODE:
        if (proto != NULL) {
            proto_sock = proto->fd;
        }
        self->fd = (PRFileDesc *) SSL_ImportFD(proto_sock, self->fd);

I32
pending(self)
    Net::NSS::SSL self;
    CODE:
        RETVAL = SSL_DataPending(self->fd);
    OUTPUT:
        RETVAL

const char *
peerhost(self)
    Net::NSS::SSL self;
    PREINIT:
        PRNetAddr addr;
        char *hostname;
    CODE:
        EVALUATE_PR_CALL(PR_GetPeerName(self->fd, &addr), "Failed to get peer addr")
        Newz(1, hostname, 16, char);
        if (PR_NetAddrToString(&addr, hostname, 16) != PR_SUCCESS) {
            Safefree(hostname);
            throw_exception_from_nspr_error("Failed to convert PRNetAddr to string");
        }
        RETVAL = hostname;
    OUTPUT:
        RETVAL

I32
peerport(self)
    Net::NSS::SSL self;
    PREINIT:
        PRNetAddr addr;
    CODE:
        EVALUATE_PR_CALL(PR_GetPeerName(self->fd, &addr), "Failed to get peer addr")
        RETVAL = addr.inet.port;
    OUTPUT:
        RETVAL

I32
keysize(self)
    Net::NSS::SSL self;
    PREINIT:
        int keysize;
    CODE:
        EVALUATE_SEC_CALL(SSL_SecurityStatus(self->fd, NULL, NULL, &keysize, NULL, NULL, NULL), 
                          "Failed to get session key length")
        RETVAL = keysize;
    OUTPUT:
        RETVAL

I32
secret_keysize(self)
    Net::NSS::SSL self;
    PREINIT:
        int secret_keysize;
    CODE:
        EVALUATE_SEC_CALL(SSL_SecurityStatus(self->fd, NULL, NULL, NULL, &secret_keysize, NULL, NULL), 
                         "Failed to get session secret key length")
        RETVAL = secret_keysize;
    OUTPUT:
        RETVAL

const char *
cipher(self)
    Net::NSS::SSL self;
    PREINIT:
        char *cipher;
    CODE:
        EVALUATE_SEC_CALL(SSL_SecurityStatus(self->fd, NULL, &cipher, NULL, NULL, NULL, NULL),
                                             "Failed to get session cipher")
        RETVAL = savepv(cipher);
        PR_Free(cipher);
    OUTPUT:
        RETVAL

const char *
issuer(self)
    Net::NSS::SSL self;
    PREINIT:
        char *issuer;
    CODE:
        EVALUATE_SEC_CALL(SSL_SecurityStatus(self->fd, NULL, NULL, NULL, NULL, &issuer, NULL),
                                             "Failed to get session issuer")
        RETVAL = savepv(issuer);
        PR_Free(issuer);
    OUTPUT:
        RETVAL

const char *
subject(self)
    Net::NSS::SSL self;
    PREINIT:
        char *subject;
    CODE:
        EVALUATE_SEC_CALL(SSL_SecurityStatus(self->fd, NULL, NULL, NULL, NULL, NULL, &subject),
                                             "Failed to get session subject")
        RETVAL = savepv(subject);
        PR_Free(subject);
    OUTPUT:
        RETVAL
        
void
set_option(self, option, on)
    Net::NSS::SSL self;
    PRInt32 option;
    PRBool on;
    CODE:
        EVALUATE_SEC_CALL(SSL_OptionSet(self->fd, option, on), "Failed to set option")
        
PRBool
get_option(self, option)
    Net::NSS::SSL self;
    PRInt32 option;
    PREINIT:
        PRBool on;
    CODE:
        EVALUATE_SEC_CALL(SSL_OptionGet(self->fd, option, &on), "Failed to get option")
        RETVAL = on;
    OUTPUT:
        RETVAL

void
close(self)
    Net::NSS::SSL self;
    CODE:
        if (self->fd != NULL) {
            EVALUATE_PR_CALL(PR_Close(self->fd), "Failed to close socket")
            self->fd = NULL;
            self->connected = PR_FALSE;
        }        

Crypt::NSS::Certificate
peer_certificate(self)
    Net::NSS::SSL self;
    PREINIT:
        CERTCertificate * cert;
    CODE:
        cert = SSL_PeerCertificate(self->fd);
        if (cert == NULL) {
            XSRETURN_UNDEF;
        }
        RETVAL = cert;
    OUTPUT:
        RETVAL
        
MODULE = Crypt::NSS     PACKAGE = Crypt::NSS::Certificate

void
DESTROY(self)
    Crypt::NSS::Certificate self;
    CODE:
        if (self != NULL) {
            CERT_DestroyCertificate(self);
        }
        
MODULE = Crypt::NSS     PACKAGE = Crypt::NSS::PKCS11

void
set_password_func(pkg, func)
    const char * pkg;
    SV * func;
    CODE:
        if (PasswordFunc != NULL) {
            SvREFCNT_dec(PasswordFunc);
        }
        PasswordFunc = SvREFCNT_inc(func);
        
MODULE = Crypt::NSS        PACKAGE = Crypt::NSS::SSL
PROTOTYPES: DISABLE

void
set_option_default(pkg, option, on)
    const char * pkg;
    PRInt32 option;
    PRBool  on;
    CODE:
        EVALUATE_SEC_CALL(SSL_OptionSetDefault(option, on), "Failed to set option default")

PRBool
get_option_default(pkg, option)
    const char * pkg;
    PRInt32 option;
    PREINIT:
        PRBool on;
    CODE:
        EVALUATE_SEC_CALL(SSL_OptionGetDefault(option, &on), "Failed to get option default")
        RETVAL = on;
    OUTPUT:
        RETVAL

void
set_cipher_default(pkg, cipher, on)
    const char * pkg;
    PRInt32 cipher;
    PRBool  on;
    CODE:
        EVALUATE_SEC_CALL(SSL_CipherPrefSetDefault(cipher, on), "Failed to set cipher default")

PRBool
get_cipher_default(pkg, cipher)
    const char * pkg;
    PRInt32 cipher;
    PREINIT:
        PRBool on;
    CODE:
        EVALUATE_SEC_CALL(SSL_CipherPrefGetDefault(cipher, &on), "Failed to get cipher default")
        RETVAL = on;
    OUTPUT:
        RETVAL

AV *
get_implemented_cipher_ids(pkg)
    const char * pkg;
    PREINIT:
        AV *ciphers = newAV();
        I32 i;
    CODE:
        for (i = 0; i < SSL_NumImplementedCiphers; i++) {
            av_push(ciphers, newSViv(SSL_ImplementedCiphers[i]));
        }
        RETVAL = ciphers;
    OUTPUT:
        RETVAL
        
void
set_cipher_suite(pkg, suite)
    const char * pkg;
    const char * suite;
    PREINIT:
        SECStatus status;
    CODE:
        if (strEQ(suite, "US") || strEQ(suite, "Domestic")) {
            status = NSS_SetDomesticPolicy();
        }
        else if (strEQ(suite, "France")) {
            status = NSS_SetFrancePolicy();
        }
        else if (strEQ(suite, "International") || strEQ(suite, "Export")) {
            status = NSS_SetExportPolicy();
        }
        else {
            croak("No cipher suite for '%s' exists", suite);
        }
        
        if (status != SECSuccess) {
            throw_exception_from_nspr_error("Failed to set cipher suite");
        }
        
void
clear_session_cache(pkg)
    const char * pkg;
    CODE:
        SSL_ClearSessionCache();

void
config_server_session_cache(pkg, args)
    const char * pkg;
    HV * args;
    PREINIT:
        int maxCacheEntries = 0;
        PRInt32 ssl2_timeout = 0;
        PRInt32 ssl3_timeout = 0;
        const char *data_dir = NULL;
        bool shared = FALSE;
        SV **value;
    CODE:
        if ((value = hv_fetch(args, "maxCacheEntries", 15, 0)) != NULL) {
            maxCacheEntries = SvIV(*value);
        }
        if ((value = hv_fetch(args, "ssl2_timeout", 12, 0)) != NULL) {
            ssl2_timeout = SvIV(*value);
        }
        if ((value = hv_fetch(args, "ssl3_timeout", 12, 0)) != NULL) {
            ssl3_timeout = SvIV(*value);
        }
        if ((value = hv_fetch(args, "data_dir", 8, 0)) != NULL) {
            data_dir = SvPV_nolen(*value);
        }
        if ((value = hv_fetch(args, "shared", 6, 0)) != NULL) {
            shared = SvTRUE(*value);
        }
        if (!shared) {
            EVALUATE_SEC_CALL(SSL_ConfigServerSessionIDCache(maxCacheEntries, ssl2_timeout, ssl3_timeout, data_dir),
                                                             "Failed to config server session cache")
        }
        else {
            EVALUATE_SEC_CALL(SSL_ConfigMPServerSIDCache(maxCacheEntries, ssl2_timeout, ssl3_timeout, data_dir),
                                                         "Failed to config shared server session cache")
        }
    
MODULE = Crypt::NSS		PACKAGE = Crypt::NSS		
PROTOTYPES: DISABLE

const char *
config_dir(pkg)
    const char * pkg;
    CODE:
        RETVAL = savepv(config_dir);
    OUTPUT:
        RETVAL

bool
set_config_dir(pkg, dir)
    const char * pkg;
    const char * dir;
    CODE:
        if (!NSS_IsInitialized()) {
            config_dir = dir;
            RETVAL = TRUE;
        }
        else
            RETVAL = FALSE;
    OUTPUT:
        RETVAL

SECStatus
initialize(pkg)
    const char * pkg;
    CODE:
        if (!NSS_IsInitialized()) {
            RETVAL = NSS_Init(config_dir);
            PK11_SetPasswordFunc(pkcs11_password_func);
        }
        else
            RETVAL = SECFailure;
    OUTPUT:
        RETVAL

bool
is_initialized(pkg)
    const char * pkg;
    CODE:
        RETVAL = (bool) NSS_IsInitialized();
    OUTPUT:
        RETVAL
    
BOOT:
    config_dir = ".";