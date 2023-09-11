#include <fstream>
#include "openssl/ssl.h"
#include "openssl/rand.h"

#include "iostream"

#include "path.h"


int main()
{
     // инициализация
     const size_t buf_size = 64 * 1024;
     const size_t block_size = 16;

     // выделение памяти под буфера
     unsigned char* in_buf = new unsigned char[ buf_size ];
     unsigned char* out_buf = new unsigned char[ buf_size + block_size ];
     unsigned char* iv = new unsigned char[ iv_size ];
     unsigned char* auth_chipper = new unsigned char[ auth_token_size ];

     // генерируем вектор инициализации
     if( 1 != RAND_bytes(iv, iv_size ) )
     {
          std::cout << "Error on generate iv";
          return -1;
     }

     // создаем контекст шифрования
     EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
     if( !ctx )
     {
          std::cout << "Error allocate memory";
          return -1;
     }

     // инициализируем шифрование
     if( EVP_EncryptInit( ctx, EVP_aes_256_gcm(), reinterpret_cast<const unsigned char*>( key.c_str() ), iv ) != 1 )
     {
          EVP_CIPHER_CTX_free( ctx );
          std::cout << "Error encrypt init!";
          return -1;
     }

     // записывает IV в файл
     std::ofstream outStr;
     outStr.open( dst_path, std::ofstream::out | std::ofstream::binary );
     if( !outStr.is_open() )
     {
          EVP_CIPHER_CTX_free( ctx );
          std::cout << "Open dst file error";
          return -1;
     }
     outStr.write( reinterpret_cast< const char* >( iv ), iv_size );

     // шифруем файл
     std::ifstream inStr( src_path, std::ofstream::in | std::ofstream::binary );
     if( !inStr.is_open() )
     {
          EVP_CIPHER_CTX_free( ctx );
          std::cout << "Open src file error";
          return -1;
     }
     while( !inStr.eof() )
     {
          size_t in_bytes = inStr.read( reinterpret_cast< char* >(in_buf), buf_size ).gcount();
          int out_nbytes = 0;
          if( 1 != EVP_EncryptUpdate( ctx, out_buf, &out_nbytes, in_buf, in_bytes ) )
          {
               EVP_CIPHER_CTX_free( ctx );
               std::cout << "EVP_EncryptUpdate error";
               return -1;
          }
          outStr.write( reinterpret_cast< const char* >( out_buf ), out_nbytes );
     }
     // завершаем шифрование(дополняем последний блок)
     int out_nbytes = 0;
     if( 1 != EVP_EncryptFinal( ctx, out_buf, &out_nbytes ) )
     {
          EVP_CIPHER_CTX_free( ctx );
          std::cout << "EVP_EncryptFinal error";
          return -1;
     }

     outStr.write( reinterpret_cast< const char* >(out_buf), out_nbytes );

     // получаем аутентификационный жетон
     if( 1 != EVP_CIPHER_CTX_ctrl( ctx, EVP_CTRL_GCM_GET_TAG, auth_token_size, auth_chipper ) )
     {
          EVP_CIPHER_CTX_free( ctx );
          std::cout << "EVP_CIPHER_CTX_ctrl error";
          return -1;
     }
     outStr.write( reinterpret_cast< const char* >( auth_chipper ), auth_token_size );

     // очищаем контекст
     EVP_CIPHER_CTX_free( ctx );
     return 0;
}