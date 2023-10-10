#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <iostream>
#include <vector>

#include "help_func.h"

/// @param mem_rbio - BIO памяти, откуда SSL читает шифртекст
/// @param mem_wbio - BIO памяти, куда SSL записывет шифртекст
/// @param tcp_bio - BIO подключения, который читает и записывает в сеть
/// @param want_read - true - происходит не только запись данных в сеть, но и чтение из сети
/// @refurn 1 - в случае успеха, иначе false
int service_bios( BIO* mem_rbio, BIO* mem_wbio, BIO* tcp_bio, bool want_read )
{
     std::vector< char > buffer;
     buffer.resize( 16 * 1024 );

     // записываем ожидающие данные в сеть
     while( BIO_pending( mem_wbio ) )
     {
          int nbytes_read = BIO_read( mem_wbio, &buffer[ 0 ], buffer.size() );
          int nbytes_written_total = 0;
          while( nbytes_written_total < nbytes_read )
          {
               int nbytes_written = BIO_write( tcp_bio, &buffer[ 0 ] + nbytes_written_total, nbytes_read - nbytes_written_total );
               if( nbytes_written > 0 )
               {
                    nbytes_written_total += nbytes_written;
                    continue;
               }
               std::cerr << "Error write data to socket" << std::endl;
               return 0;
          }
     }
     if( want_read )
     {
          int nbytes_read = BIO_read( tcp_bio, &buffer[ 0 ], buffer.size() );
          if( nbytes_read > 0 )
          {
               BIO_write( mem_rbio, &buffer[ 0 ], nbytes_read );
          }
          else
          {
               std::cerr << "Error read data from socket" << std::endl;
               return 0;
          }
     }
     return 1;
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
     std::string cert_path;
     if( argc > 3 )
     {
          cert_path = argv[ 3 ];
     }
     // выделяем буферы для чтения и записи
     const size_t buf_size  = 16 * 1024;
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

     // устаналиваем TCP соединение
     BIO* tcp_bio = BIO_new_connect( address.c_str() );
     BIO_set_conn_port( tcp_bio, port.c_str() );

     err = BIO_do_connect( tcp_bio );
     if( err <= 0 )
     {
          std::cerr << "Error connect to server";
          return -1;
     }

     // создаём читающий BIO
     BIO* mem_rbio = BIO_new( BIO_s_mem() );

     // чтобы избежать ошибки конца файла в случае пустого BIO
     BIO_set_mem_eof_return( mem_rbio, -1 );

     // создаем записывающий BIO
     BIO* mem_wbio = BIO_new( BIO_s_mem() );
     BIO_set_mem_eof_return( mem_wbio, -1 );

     // создаем объект TLS
     SSL* ssl = SSL_new( ctx );

     // присоединяем читающий и пишущий BIO
     SSL_set_bio( ssl, mem_rbio, mem_wbio );


     // для расширения SNI(для случаев с общим хостингом) задаем имя хоста
     SSL_set_tlsext_host_name( ssl, address.c_str() );

     // имя сервера для проверки сертификата по CN
     SSL_set1_host( ssl, address.c_str() );

     // tls квитированое
     while( true )
     {
          err = SSL_connect( ssl );
          int ssl_error = SSL_get_error( ssl, err );
          if( ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE || BIO_pending( mem_wbio ) )
          {
               int service_bios_err = service_bios( mem_rbio, mem_wbio, tcp_bio, SSL_want_read( ssl ) );
               if( service_bios_err != 1 )
               {
                    std::cerr << "Error in TLS handshake" << std::endl;
                    return -1;
               }
               continue;
          }
          break;
     }
     if( err <= 0 )
     {
          std::cerr << "Error in TLS handshake: " << SSL_get_error( ssl, err ) << std::endl;
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
               int nbytes_written = SSL_write( ssl, data_to_send.c_str() + nbytes_written_total, data_to_send.size() - nbytes_written_total );
               if( nbytes_written > 0 )
               {
                    nbytes_written_total += nbytes_written;
                    continue;
               }
               int ssl_error = SSL_get_error( ssl, err );
               if( ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE || BIO_pending( mem_wbio ) )
               {
                    int service_bios_err = service_bios( mem_rbio, mem_wbio, tcp_bio, SSL_want_read( ssl ) );
                    if( service_bios_err != 1 )
                    {
                         std::cerr << "Service bios error" << std::endl;
                         return -1;
                    }
                    continue;
               }
               std::cerr << "Error send data to server: " << ssl_error << std::endl;
               return -1;
          }

          bool result = false;
          std::string response;
          while( true )
          {
               int service_bios_err = 1;
               if( !BIO_pending( mem_rbio ) )
               {
                    service_bios_err = service_bios( mem_rbio, mem_wbio, tcp_bio, true );
               }
               if( service_bios_err != 1 )
               {
                    std::cerr << "Error read from socket" << std::endl;
                    break;
               }
               int nbytes_read = SSL_read( ssl, in_buf, buf_size );
               if( nbytes_read > 0 )
               {
                    response.append( in_buf, in_buf + nbytes_read );
                    if( response.at( response.size() - 1 ) == '\n' )
                    {
                         std::cout << "Server answer!" << std::endl;
                         std::cout << response;
                         result = true;
                         break;
                    }
                    continue;
               }

               int ssl_error = SSL_get_error( ssl, err );
               if( ssl_error == SSL_ERROR_NONE || ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE ||
                       BIO_pending( mem_wbio ) )
               {
                    continue;
               }

               if( ssl_error == SSL_ERROR_ZERO_RETURN )
               {
                    std::cerr << "Connection closed by server" << std::endl;
                    break;
               }
               std::cerr << "TLS error: " << ssl_error << std::endl;
               break;
          }
          if( !result )
          {
               break;
          }
     }

     // размыкаем соединение
     while( true )
     {
          err = SSL_shutdown( ssl );
          int ssl_error = SSL_get_error( ssl, err );
          if( ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE || BIO_pending( mem_wbio ) )
          {
               int service_bios_err = service_bios( mem_rbio, mem_wbio, tcp_bio, SSL_want_read( ssl ) );
               if( service_bios_err != 1 )
               {
                    std::cerr << "Service bios error" << std::endl;
                    return -1;
               }
               continue;
          }
          break;
     }
     if( err != 1 )
     {
          std::cerr << "Error TLS shutdown" << std::endl;
          return -1;
     }

     SSL_free( ssl );
     BIO_free( tcp_bio );
     SSL_CTX_free( ctx );

     delete[] in_buf;

     return 0;
}