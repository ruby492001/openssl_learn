#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <iostream>

#include "help_func.h"

X509* load_fixed_cert( const std::string& cert_path )
{
     FILE* file = fopen( cert_path.c_str(), "rb" );
     if( !file )
     {
          return nullptr;
     }
     X509* cert = PEM_read_X509( file, nullptr, nullptr, nullptr );
     fclose( file );
     return cert;
}


int cert_verify_callback( X509_STORE_CTX* x509_store_ctx, void* arg )
{
     // получаем ожидаемый сертификат сервера
     X509* expected_server_cert = static_cast< X509* >( arg );

     // получаем текущий сертификат сервера
     X509* current_server_cert = X509_STORE_CTX_get0_cert( x509_store_ctx );

     X509_NAME* expected_cert_subject = X509_get_subject_name( expected_server_cert );
     X509_NAME* current_cert_subject = X509_get_subject_name( current_server_cert );
     std::cout << "Expected server cert subject is: " << X509_NAME_to_string( expected_cert_subject ) << std::endl;
     std::cout << "Current server cert subject is:" << X509_NAME_to_string( current_cert_subject ) << std::endl;

     // прописываем текущий сертификат и его глубину в контексте
     X509_STORE_CTX_set_current_cert( x509_store_ctx, current_server_cert );
     X509_STORE_CTX_set_depth( x509_store_ctx, 0 );

     // сравниваем ожидаемый и полученный сертификаты
     int cmp = X509_cmp( current_server_cert, expected_server_cert );
     if( cmp == 0 )
     {
          std::cout << "Verification completed! Continue..." << std::endl;
          X509_STORE_CTX_set_error( x509_store_ctx, X509_V_OK );
          return 1;
     }
     else
     {
          std::cout << "Verification failed! Aborted" << std::endl;
          X509_STORE_CTX_set_error( x509_store_ctx, X509_V_ERR_APPLICATION_VERIFICATION );
          return 0;
     }
}

int main( int argc, char** argv )
{
     if( argc < 3 )
     {
          std::cerr << "Invalid usage";
          return -1;
     }
     const std::string address = argv[ 1 ];
     const std::string port = argv[ 2 ];
     const std::string fixed_cert_path = argv[ 3 ];

     // выделяем буферы для чтения и записи
     const size_t buf_size  = 16 * 1024;
     unsigned char* in_buf = new unsigned char[ buf_size ];

     // создаем контекст SSL
     SSL_CTX* ctx = SSL_CTX_new( TLS_client_method() );

     // загружаем закрепленный сертификат сервера
     X509* server_cert = load_fixed_cert( fixed_cert_path );
     if( !server_cert )
     {
          std::cerr << "Load fixed cert error!" << std::endl;
          return -1;
     }

     // устанавливаем "большой" обратный вызов
     SSL_CTX_set_cert_verify_callback( ctx, cert_verify_callback, server_cert );

     // устанавливаем обязательную проверку сертификата сервера
     SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER, nullptr );
     // устанавливаем функцию обратного вызова
     //SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER, verify_callback );

     // устанавливаем флаг автоматической обработки ошибок SSL_ERROR_WANT_READ и SSL_ERROR_WANT_WRITE
     SSL_CTX_set_mode( ctx, SSL_MODE_AUTO_RETRY );

     // устанавливаем функкию проверки CRL
     X509_STORE* x509_store = SSL_CTX_get_cert_store( ctx );
     //X509_STORE_set_lookup_crls( x509_store, lookup_crls );
     //X509_STORE_set_flags( x509_store, X509_V_FLAG_CRL_CHECK );

     // активируем TLS-расширение Certificate Status Request
     //SSL_CTX_set_tlsext_status_type( ctx, TLSEXT_STATUSTYPE_ocsp );

     // устанавливаем callback для обработки вшивания OCSP:
     //SSL_CTX_set_tlsext_status_cb( ctx, ocsp_callback );

     // создаем SSL BIO
     BIO* ssl_bio = BIO_new_ssl_connect( ctx );
     BIO_set_conn_hostname( ssl_bio, address.c_str() );

     // задаем адресс и порт удаленного сервера
     BIO_set_conn_port( ssl_bio, port.c_str() );

     // извлекаем SSL из SSL BIO
     SSL* ssl = nullptr;
     BIO_get_ssl( ssl_bio, &ssl );

     // для расширения SNI(для случаев с общим хостингом) задаем имя хоста
     SSL_set_tlsext_host_name( ssl, address.c_str() );

     // имя сервера для проверки сертификата по CN
     SSL_set1_host( ssl, address.c_str() );

     // устанавливаем "тестовые" данные, до которых можно достучаться из функции обратного вызова
     const std::string test_str = "This is test str!";
     SSL_set_app_data( ssl, &test_str );

     // устанавливаем TLS-соединение
     int err = BIO_do_connect( ssl_bio );
     if( err <= 0 )
     {
          std::cerr << "Error connect to server" << std::endl;
          int err_code = ERR_peek_error();
          if( err_code )
          {
               char error[ 512 ];

               std::cerr << "Error from openssl: " << ERR_error_string( sizeof( error ), error ) << std::endl;
               std::cerr << ERR_reason_error_string( err_code ) << std::endl;
          }
          ERR_clear_error();
          return -1;
     }
     while( true )
     {
          std::cout << "Enter data to send" << std::endl;
          std::string data_to_send;

          std::cin >> data_to_send;
          data_to_send += "\n";
          int nbytes_written = BIO_write( ssl_bio, data_to_send.c_str(), data_to_send.size() );
          if( nbytes_written != data_to_send.size() )
          {
               std::cerr << "Write data error";
               break;
          }

          bool result = false;
          std::string response;
          while( true )
          {
               int nbytes_read = BIO_read( ssl_bio, in_buf, buf_size );
               if( nbytes_read <= 0 )
               {
                    int ssl_error = SSL_get_error( ssl, nbytes_read );
                    if( ssl_error != SSL_ERROR_ZERO_RETURN )
                    {
                         std::cerr << "Error in read data from server: " << ssl_error;
                    }
                    break;
               }

               response.append( in_buf, in_buf + nbytes_read );
               if( !response.empty() && response.at( response.size() - 1 ) == '\n')
               {
                    std::cout << "Server answer!" << std::endl;
                    std::cout << response;
                    result = true;
                    break;
               }
          }
          if( !result )
          {
               break;
          }
     }

     // закрываем нашу сторону соединения
     BIO_ssl_shutdown( ssl_bio );

     // освобождаем ресурсы
     if( ssl_bio )
     {
          BIO_free_all( ssl_bio );
     }
     if( ctx )
     {
          SSL_CTX_free( ctx );
     }
     X509_free( server_cert );
     delete[] in_buf;

     return 0;
}