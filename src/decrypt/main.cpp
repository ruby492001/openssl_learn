#include <fstream>
#include "openssl/ssl.h"
#include "openssl/rand.h"

#include "iostream"

#include "path.h"

int main()
{
     // выделение памяти под буфера
     const size_t buf_size = 64 * 1024;
     const size_t block_size = 16;

     unsigned char* in_buf = new unsigned char[ buf_size ];
     unsigned char* out_buf = new unsigned char[ buf_size + block_size ];
     unsigned char* iv = new unsigned char[ iv_size ];
     unsigned char* auth_token = new unsigned char[ auth_token_size ];

     // открываем шифрованный файл
     std::ifstream inp_stream( dst_path, std::ifstream::in | std::ifstream::binary );
     if( !inp_stream.is_open() )
     {
          std::cout << "Error open input file";
          return -1;
     }

     // открываем выходной файл
     std::ofstream out_str( decrypted_path, std::ios::out | std::ios::binary );
     if( !out_str.is_open() )
     {
          std::cout << "Error open output file";
          return -1;
     }

     // получаем размер файла
     inp_stream.seekg( 0, std::ios::end );
     const size_t file_size = inp_stream.tellg();
     const size_t auth_token_begin_pos = file_size - auth_token_size;
     inp_stream.seekg( 0, std::ios::beg );

     // читаем вектор инициализации
     size_t curr_pos = inp_stream.read( reinterpret_cast< char* >( iv ), iv_size ).tellg();
     if( curr_pos != iv_size )
     {
          std::cout << "Error read iv";
          return -1;
     }

     // инициализируем расшифрование
     EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
     if( 1 != EVP_DecryptInit( ctx, EVP_aes_256_gcm(), reinterpret_cast< const unsigned char* >( key.c_str() ), iv ) )
     {
          std::cout << "EVP_DecryptInit error";
          EVP_CIPHER_CTX_free( ctx );
          return -1;
     }

     while( inp_stream.tellg() < auth_token_begin_pos )
     {
          size_t want_to_read_size = std::min( auth_token_begin_pos - inp_stream.tellg(), buf_size );
          size_t in_bytes = inp_stream.read( reinterpret_cast< char* > ( in_buf ), want_to_read_size ).gcount();
          int out_bytes = 0;
          if( 1 != EVP_DecryptUpdate( ctx, out_buf, &out_bytes, in_buf, in_bytes ) )
          {
               std::cout << "EVP_DecryptUpdate error";
               EVP_CIPHER_CTX_free( ctx );
               return -1;
          }
          out_str.write( reinterpret_cast< const char* >(out_buf), out_bytes );
     }
     if( inp_stream.read( reinterpret_cast< char* >( auth_token ), auth_token_size ).gcount() != auth_token_size )
     {
          std::cout << "Read auth token error";
          EVP_CIPHER_CTX_free( ctx );
          return -1;
     }
     if( 1 != EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_SET_TAG, auth_token_size, auth_token ) )
     {
          std::cout << "EVP_CIPHER_CTX_ctrl error";
          EVP_CIPHER_CTX_free( ctx );
          return -1;
     }
     int out_bytes = 0;
     if( 1 != EVP_DecryptFinal( ctx, out_buf, &out_bytes ) )
     {
          std::cout << "EVP_DecryptFinal error";
          EVP_CIPHER_CTX_free( ctx );
          return -1;
     }
     out_str.write( reinterpret_cast< const char* >( out_buf ), out_bytes );
     EVP_CIPHER_CTX_free( ctx );
     return 0;
}