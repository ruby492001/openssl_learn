#pragma once

#include "openssl/ssl.h"
#include <openssl/err.h>

#include "iostream"


int verify_callback( int preverify_ok, X509_STORE_CTX* x509_store_ctx );
std::string ASN1_INTEGER_to_string( ASN1_INTEGER* serial_number );
std::string X509_NAME_to_string( const X509_NAME* name );