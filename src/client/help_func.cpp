#include "help_func.h"
#include <openssl/x509v3.h>


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

     if( error_code == X509_V_ERR_UNABLE_TO_GET_CRL )
     {
          return 1;
     }
     return preverify_ok;
}


STACK_OF(X509_CRL)* lookup_crls( const X509_STORE_CTX* x509_store_ctx, const X509_NAME* x509_name )
{
     // получаем текущий сертификат
     X509* current_cert = X509_STORE_CTX_get_current_cert( x509_store_ctx );

     // печатаем информацию о текущм сертификате
     int depth = X509_STORE_CTX_get_error_depth( x509_store_ctx );
     X509_NAME* current_cert_subject = X509_get_subject_name( current_cert );
     const std::string subject = X509_NAME_to_string( current_cert_subject );

     std::cout << "Lookup crls: Depth: " << depth << " Name of subject:" << subject << std::endl;

     // получаем точки распространения crl
     // CRL_DIST_POINTS - псевдоним для STACK_OF(DIST_POINT)
     CRL_DIST_POINTS* crl_dist_points = ( CRL_DIST_POINTS* )X509_get_ext_d2i( current_cert, NID_crl_distribution_points,
                                                                              nullptr, nullptr );

     // проходимся по всем точкам распространения и пытаемся скачать crl
     int crl_dist_point_count = sk_DIST_POINT_num( crl_dist_points );
     for( int idx = 0; idx < crl_dist_point_count; idx++ )
     {
          DIST_POINT* dist_point = sk_DIST_POINT_value( crl_dist_points, idx );
          X509_CRL* crl = download_crl_from_dist_point( dist_point );
          if( !crl )
          {
               continue;
          }
          STACK_OF(X509_CRL)* crls = sk_X509_CRL_new_null();
          sk_X509_CRL_push( crls, crl );
          return crls;
     }
     return nullptr;
}

X509_CRL* download_crl_from_dist_point( const DIST_POINT* dist_point )
{
     // получаем компьютерные имена
     const DIST_POINT_NAME* dist_point_name = dist_point->distpoint;
     if( !dist_point_name || dist_point_name->type != 0 )
     {
          return nullptr;
     }
     const GENERAL_NAMES* general_names = dist_point_name->name.fullname;
     if( !general_names )
     {
          return nullptr;
     }
     // проходимся по общим именам, ищем URL
     for( int idx = 0; idx < sk_GENERAL_NAME_num( general_names ); idx++ )
     {
          const GENERAL_NAME* general_name = sk_GENERAL_NAME_value( general_names, idx );
          int general_name_type = 0;
          const ASN1_STRING* general_name_asn1_string = ( const ASN1_STRING* ) GENERAL_NAME_get0_value( general_name, &general_name_type );
          if( general_name_type != GEN_URI )
          {
               continue;
          }
          std::string url = ( const char* ) ASN1_STRING_get0_data( general_name_asn1_string );

          X509_CRL* crl = nullptr;
          // проверяем, что имя начинается с http
          if( url.find( "http://") != std::string::npos )
          {
               // пытаемся скачать crl
               std::cout << "Found CRL URL: " << url << std::endl;
               crl = download_crl_from_http_url( url );
          }
          if( url.find( '/' ) == 0 )
          {
               std::cout << "Found CRL LOCAL: " << url << std::endl;
               crl = load_crl_from_local( url );

          }
          if( !crl )
          {
               std::cout << "Error load crl from: " << url << std::endl;
               continue;
          }
          std::cout << "Downloaded CRL from: " << url << std::endl;
          return crl;

     }
     return nullptr;
}


X509_CRL* download_crl_from_http_url( const std::string& url )
{
     BIO* bio = OSSL_HTTP_get( url.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 65536, nullptr, nullptr, 1, 50 * 1024 * 1024, 60 );

     // d - DER, i - internal(структура в памяти), X509_CRL - тип объекта, bio - объект BIO, fp - указатель на файл
     X509_CRL* crl = d2i_X509_CRL_bio( bio, nullptr );
     BIO_free( bio );
     return crl;
}


X509_CRL* load_crl_from_local( const std::string& url )
{
     BIO* bio = BIO_new( BIO_s_file() );
     BIO_read_filename( bio, url.c_str() );
     X509_CRL* crl = d2i_X509_CRL_bio( bio, nullptr );
     BIO_free( bio );
     return crl;
}

