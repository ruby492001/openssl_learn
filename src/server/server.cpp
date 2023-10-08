#include "openssl/ssl.h"
#include <openssl/err.h>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include <thread>

#include "iostream"

bool exit_flag = false;


X509* load_cert( const std::string& path )
{
     FILE* file = fopen( path.c_str(), "rb" );
     if( !file )
     {
          return nullptr;
     }
     X509* cert = PEM_read_X509( file, nullptr, nullptr, nullptr );
     fclose( file );
     return cert;
}

STACK_OF( X509 )* load_certs( const std::vector< std::string >& certs_path )
{
     STACK_OF( X509 )* result = sk_X509_new_null();
     for( const std::string& str: certs_path )
     {
          sk_X509_push( result, load_cert( str ) );
     }
     return result;
}


EVP_PKEY* load_private_key( const std::string& path )
{
     FILE* file = fopen( path.c_str(), "rb" );
     if( !file )
     {
          return nullptr;
     }
     EVP_PKEY* result = PEM_read_PrivateKey( file, nullptr, nullptr, nullptr );
     fclose( file );
     return result;
}


void handle_accepted_connection( BIO* ssl_bio )
{
     int err = BIO_do_handshake( ssl_bio );
     if( err <= 0 )
     {
          std::cerr << "Error handshake connection!";
          return;
     }

     // извлекаем SSL из SSL BIO
     SSL* ssl = nullptr;
     BIO_get_ssl( ssl_bio, &ssl );


     const size_t buf_size = 1024 * 4;
     unsigned char* in_buf = new unsigned char[ buf_size ];
     std::string result;
     while( !exit_flag )
     {
          int nbytes_read = BIO_read( ssl_bio, in_buf, buf_size );
          if( nbytes_read <= 0 )
          {
               if( exit_flag )
               {
                    std::cout << "Client connection was interrupted" << std::endl;
                    break;
               }
               int ssl_error = SSL_get_error( ssl, nbytes_read );
               if( ssl_error != SSL_ERROR_ZERO_RETURN )
               {
                    std::cerr << "Error in read data from client: " << ssl_error;
               }
               break;
          }

          result.append( in_buf, in_buf + nbytes_read );
          if( !result.empty() && result.at( result.size() - 1 ) == '\n' )
          {
               std::cout << "Reading complete!" << std::endl;
               std::cout << "Client write:" << result;
          }
          else
          {
               continue;
          }
          if( result == "exit\n" )
          {
               std::cout << "Client request exit";
               break;
          }

          std::string answer = "You are write:" + result;
          result.clear();

          int bytes_written = BIO_write( ssl_bio, answer.c_str(), answer.size() );
          if( bytes_written != answer.size() )
          {
               std::cerr << "Error send data to client" << std::endl;
          }
          std::cout << "Data was sent to client" << std::endl;
     }

     // закрываем соединение
     BIO_ssl_shutdown( ssl_bio );

     // освобождаем память
     BIO_free_all( ssl_bio );
     delete[] in_buf;
}

std::vector< std::shared_ptr< std::thread > > threads;

void handle_connection( BIO* ssl_bio )
{
     std::shared_ptr< std::thread > trd = std::make_shared< std::thread >( handle_accepted_connection, ssl_bio );
     threads.push_back( trd );
}




void signal_handler( int )
{
     std::cout << "Interrupted!" << std::endl;
     exit_flag = true;
}




int main( int argc, char** argv )
{
     struct sigaction sa;
     // устанавливаем обработчик
     bool sig_handle_res = [ & ] () -> bool
     {
          memset( &sa, 0, sizeof( sa ) );
          sa.sa_handler = &signal_handler;
          sa.sa_flags = SA_NOCLDSTOP;
          if( sigfillset( &sa.sa_mask ) < 0 )
          {
               return false;
          }
          sigaddset( &sa.sa_mask, SIGINT );

          if( sigaction( SIGINT, &sa, nullptr ) < 0 )
          {
               return false;
          }
          return true;
     }();

     if( !sig_handle_res )
     {
          std::cerr << "Error set sig handle" << std::endl;
          return -1;
     }
     if( argc < 4 )
     {
          std::cerr << "Invalid usage";
          return -1;
     }
     const std::string port_value = argv[ 1 ];
     const std::string private_key_path = argv[ 2 ];
     const std::string server_cert_path = argv[ 3 ];
     std::vector< std::string > cert_files_path;
     for( int idx = 4; idx < argc; idx++ )
     {
          cert_files_path.emplace_back(argv[ idx ] );
     }

     // создаем контекст SSL
     SSL_CTX* ctx = SSL_CTX_new( TLS_server_method() );

     // загружаем сертификат сервера, приватный ключ сервера и цепочку сертификатов
     X509* server_cert  = load_cert( server_cert_path );
     EVP_PKEY* private_key = load_private_key( private_key_path );
     STACK_OF( X509 )* cert_chain = load_certs( cert_files_path );
     if( !server_cert )
     {
          std::cerr << "Error load server cert" << std::endl;
          return -1;
     }
     if( !private_key )
     {
          std::cerr << "Error load private key" << std::endl;
          return -1;
     }

     // устанавливаем контексу использование сертификата, открытого и закрытых ключей, промежуточных сертификатов
     int err = SSL_CTX_use_cert_and_key( ctx, server_cert, private_key, cert_chain, 1 );
     if( err <= 0 )
     {
          std::cerr << "Use cert and key error" << std::endl;
          return -1;
     }


     //  проверяем, что загруженная пара ключей соответствует первому сертификату
     err = SSL_CTX_check_private_key( ctx );
     if( err <= 0 )
     {
          std::cerr << "Check private key error" << std::endl;
          int error_code = ERR_peek_error();
          if( error_code )
          {
               std::cerr << ERR_reason_error_string( error_code );
          }
          return -1;
     }

     // аналогично клиенту устанавливаем SSL_MODE_AUTO_RETRY
     SSL_CTX_set_mode( ctx, SSL_MODE_AUTO_RETRY );

     // создаем объект запроса на подключение
     BIO* accept_bio = BIO_new_accept( port_value.c_str() );

     // создаем слушающий сокет
     err = BIO_do_accept( accept_bio );
     if( err <= 0 )
     {
          std::cerr << "Error start listening" << std::endl;
          return -1;
     }

     while( !exit_flag )
     {
          // принимаем соединение
          err = BIO_do_accept( accept_bio );
          if( err <= 0 )
          {
               if( exit_flag )
               {
                    break;
               }

               std::cout << "Error accept connection" << std::endl;
               int error_code = ERR_peek_error();
               if( error_code )
               {
                    std::cout << ERR_reason_error_string( error_code );
               }
               continue;
          }

          // отсоединяем BIO соединения от BIO приема
          BIO* current_socket = BIO_pop( accept_bio );

          // создаем новый SSL BIO
          BIO* ssl_bio = BIO_new_ssl( ctx, 0 );

          // вставляем SSL BIO перед BIO сокета
          BIO_push( ssl_bio, current_socket );

          // обрабатываем соединение
          handle_accepted_connection( ssl_bio );
     }
     BIO_free( accept_bio );
     // завершаем потоки
     for( auto& th: threads )
     {
          th->join();
     }
     return 0;
}