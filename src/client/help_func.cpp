#include "help_func.h"


std::string X509_NAME_to_string( const X509_NAME* name )
{
     BIO* mem_bio = BIO_new( BIO_s_mem() );
     X509_NAME_print_ex( mem_bio, name, 0, XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB );
     char* bio_data = nullptr;
     long bio_data_len = BIO_get_mem_data( mem_bio, &bio_data );
     std::string x509_name( bio_data, bio_data_len );
     BIO_free( mem_bio );
     return x509_name;
}


std::string ASN1_INTEGER_to_string( ASN1_INTEGER* serial_number )
{
     BIGNUM* bnser = ASN1_INTEGER_to_BN( serial_number, nullptr );

     char* hex = BN_bn2hex( bnser );
     std::string res = hex;
     BN_free( bnser );
     OPENSSL_free( hex );
     return res;
}

int verify_callback( int preverify_ok, X509_STORE_CTX* x509_store_ctx )
{
     // получаем "тестовые" данные
     int ssl_ex_data_idx = SSL_get_ex_data_X509_STORE_CTX_idx();
     SSL* ssl = static_cast< SSL* >( X509_STORE_CTX_get_ex_data( x509_store_ctx, ssl_ex_data_idx ) );
     const std::string* user_data = static_cast< const std::string* >( SSL_get_app_data( ssl ) );
     // std::cout << "User data is:" << *user_data << std::endl;

     // получаем глубингу сертификата
     int depth = X509_STORE_CTX_get_error_depth( x509_store_ctx );

     // получаем код ошибки
     int error_code = preverify_ok ? X509_V_OK : X509_STORE_CTX_get_error( x509_store_ctx );

     // преобразуем код ошибки в строку
     std::string error_string = X509_verify_cert_error_string( error_code );

     // получаем текущий сертификат
     X509* current_cert = X509_STORE_CTX_get_current_cert( x509_store_ctx );

     // получаем смведения о текущем сертификате(субъект, кто подписал, серийный номер)
     X509_NAME* current_cert_subject = X509_get_subject_name( current_cert );
     X509_NAME* current_cert_issuer = X509_get_issuer_name( current_cert );
     ASN1_INTEGER* current_serial_number = X509_get_serialNumber( current_cert );

     const std::string subject = X509_NAME_to_string( current_cert_subject );
     const std::string issuer = X509_NAME_to_string( current_cert_issuer );
     const std::string serial_num = ASN1_INTEGER_to_string( current_serial_number );

     std::cout <<   "\n\nDepth: " << depth << '\n' <<
               "Error: " << error_string << '\n' <<
               "Subject: " << subject << '\n' <<
               "Issuer: " << issuer << '\n' <<
               "Serial number: " << serial_num << "\n" << std::endl;

     return preverify_ok;
}