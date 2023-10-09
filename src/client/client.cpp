#include "openssl/ssl.h"
#include <openssl/err.h>

#include "iostream"

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

     if( depth == 1 && subject != "CN = Intermediate_1" )
     {
          return 0;
     }
     return preverify_ok;
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
     // устанавливаем функцию обратного вызова
     SSL_CTX_set_verify( ctx, SSL_VERIFY_PEER, verify_callback );

     // устанавливаем флаг автоматической обработки ошибок SSL_ERROR_WANT_READ и SSL_ERROR_WANT_WRITE
     SSL_CTX_set_mode( ctx, SSL_MODE_AUTO_RETRY );

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
     err = BIO_do_connect( ssl_bio );
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
     delete[] in_buf;

     return 0;
}