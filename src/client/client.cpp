#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <iostream>

#include "help_func.h"

int main( int argc, char** argv )
{
     if( argc < 3 )
     {
          std::cerr << "Invalid usage";
          return -1;
     }
     const std::string address = argv[ 1 ];
     const std::string port = argv[ 2 ];
     std::string cert_path;
     if( argc > 3 )
     {
          cert_path = argv[ 3 ];
     }
     // выделяем буферы для чтения и записи
     const size_t buf_size = 3;
     unsigned char* in_buf = new unsigned char[ buf_size ];

     // создаем контекст SSL
     SSL_CTX* ctx = SSL_CTX_new( TLS_client_method() );

     int err = 0;
     if( cert_path.empty() )
     {
          // загружаем корневые сертификаты из путей по умолчанию
          err = SSL_CTX_set_default_verify_paths( ctx );
     }
     else
     {
          // загружаем сертификат из файла
          err = SSL_CTX_load_verify_file( ctx, cert_path.c_str() );
     }
     if( err <= 0 )
     {
          std::cerr << "Error load trusted cert!";
          return -1;
     }

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

     // устанавливаем неблокирующий режим
     BIO_set_nbio( ssl_bio, 1 );

     // определяем переменный тайм-аута
     const unsigned int nap_ms = 100;

     // устанавливаем TLS-соединение
     err = BIO_do_connect( ssl_bio );
     while( err <= 0 && BIO_should_retry( ssl_bio ) )
     {
          int wait_err = BIO_wait( ssl_bio, 0, nap_ms );
          if( wait_err != 1 )
          {
               break;
          }
          err = BIO_do_connect( ssl_bio );
     }

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
          int nbytes_written_total = 0;
          while( nbytes_written_total < data_to_send.size() )
          {
               int nbytes_written = BIO_write( ssl_bio, data_to_send.c_str() + nbytes_written_total, data_to_send.size() - nbytes_written_total );
               if( nbytes_written > 0 )
               {
                    nbytes_written_total += nbytes_written;
                    continue;
               }
               if( BIO_should_retry( ssl_bio ) )
               {
                    int wait_error = BIO_wait( ssl_bio, 0, nap_ms );
                    if( wait_error == 1 )
                    {
                         continue;
                    }
                    else if( wait_error == 0 )
                    {
                         std::cerr << "BIO_wait timeout" << std::endl;
                    }
                    else
                    {
                         std::cerr << "BIO_wait error" << std::endl;
                    }
               }
               std::cerr << "Error write data!" << std::endl;
               return -1;
          }

          std::string response;
          bool result = true;
          while( true )
          {
               int nbytes_read = BIO_read( ssl_bio, in_buf, buf_size );
               if( nbytes_read > 0 )
               {
                    response.append( in_buf, in_buf + nbytes_read );
                    if( *response.rbegin() == '\n')
                    {
                         break;
                    }
                    continue;
               }
               if( BIO_should_retry( ssl_bio ) )
               {
                    int wait_error = BIO_wait( ssl_bio, 0, nap_ms );
                    if( wait_error == 1 )
                    {
                         continue;
                    }
                    else if( wait_error == 0 )
                    {
                         std::cerr << "BIO_wait timeout" << std::endl;
                    }
                    else
                    {
                         std::cerr << "BIO_wait error" << std::endl;
                    }
               }
               else
               {
                    std::cerr << "BIO_should_retry return false" << std::endl;
               }

               result = false;
               int ssl_error = SSL_get_error( ssl, nbytes_read );
               if( ssl_error == SSL_ERROR_ZERO_RETURN )
               {
                    std::cout << "TLS connection closed by server" << std::endl;
               }
               else
               {
                    std::cerr << "Error on read data from server: " << ssl_error << std::endl;
               }
               break;
          }
          if( !result )
          {
               break;
          }
          std::cout << "Server response is: \n" << response << std::endl;
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
     delete[] in_buf;

     return 0;
}