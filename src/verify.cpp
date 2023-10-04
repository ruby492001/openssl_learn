#include <vector>
#include "openssl/ssl.h"

#include "iostream"

STACK_OF( X509 )* load_untrusted_certs( const std::vector< std::string >& files_path )
{
     STACK_OF( X509 )* result = sk_X509_new_null();
     for( const std::string& str: files_path )
     {
          FILE* file = fopen( str.c_str(), "rb" );
          if( !file )
          {
               std::cerr << "Read file error:" << str;
               continue;
          }
          X509* cert = PEM_read_X509( file, nullptr, nullptr, nullptr );
          sk_X509_push( result , cert );
          fclose( file );
     }
     return result;
}


X509* load_target_certificate( const std::string& target_path )
{
     FILE* file = fopen( target_path.c_str(), "rb" );
     if( !file )
     {
          return nullptr;
     }
     X509* res = PEM_read_X509( file, nullptr, nullptr, nullptr );
     fclose( file );
     return res;
}


int main( int argc, char** argv )
{
     if( argc < 4 )
     {
          std::cerr << "incorrect usage";
          return -1;
     }
     const std::string verify_cert_path = argv[ 1 ];
     const std::string trusted_cert_path = argv[ 2 ];

     std::vector< std::string > untrusted_certs_path;
     for( int idx = 3; idx < argc; idx++ )
     {
          untrusted_certs_path.emplace_back( argv[ idx ] );
     }

     // загружаем доверенный сертификат
     X509_STORE* trusted_store = X509_STORE_new();
     X509_STORE_load_file( trusted_store, trusted_cert_path.c_str() );

     // загружаем недоверенные сертификаты
     STACK_OF( X509 )* untrusted_certs = load_untrusted_certs( untrusted_certs_path );

     // загружаем проверяемый сертификат
     X509* cert_to_verify = load_target_certificate( verify_cert_path );
     if( !cert_to_verify )
     {
          std::cerr << "Error load validate cert";
          return -1;
     }

     // создаем контекст проверки сертификатов
     X509_STORE_CTX* ctx = X509_STORE_CTX_new();
     X509_STORE_CTX_init( ctx, trusted_store, cert_to_verify, untrusted_certs );

     // проверяем сертификат
     int err = X509_verify_cert( ctx );
     if( err == 1 )
     {
          std::cout << "Validation complete";
     }
     else
     {
          std::string error_string = X509_verify_cert_error_string( X509_STORE_CTX_get_error( ctx ) );
          std::cout << "Validation error:" << error_string;
     }
     X509_STORE_CTX_free( ctx );
     X509_STORE_free( trusted_store );
     X509_free( cert_to_verify );
     sk_X509_pop_free( untrusted_certs, X509_free );

     return 0;
}