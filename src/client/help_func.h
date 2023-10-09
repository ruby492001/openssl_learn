#pragma once

#include "openssl/ssl.h"
#include <openssl/err.h>

#include "iostream"


int verify_callback( int preverify_ok, X509_STORE_CTX* x509_store_ctx );
std::string ASN1_INTEGER_to_string( ASN1_INTEGER* serial_number );
std::string X509_NAME_to_string( const X509_NAME* name );

// функция обратного вызова для проверки crl
STACK_OF(X509_CRL)* lookup_crls( const X509_STORE_CTX* x509_store_ctx, const X509_NAME* x509_name );

// функиця скачивания CRL с точки распространения
X509_CRL* download_crl_from_dist_point( const DIST_POINT* dist_point );

// функция загрузки crl по http url
X509_CRL* download_crl_from_http_url( const std::string& url );

// функция загрузки crl из файла
X509_CRL* load_crl_from_local( const std::string& url );
