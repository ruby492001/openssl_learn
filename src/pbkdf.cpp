#include <openssl/params.h>
#include "openssl/kdf.h"
#include "openssl/core_names.h"
#include "iostream"

const size_t key_size = 32;


int main( int argc, char* argv[] )
{
     if( argc != 3 )
     {
          std::cerr << "Invalid usage";
          return -1;
     }
     std::string password = argv[ 1 ];
     std::string hex_salt = argv[ 2 ];

     // получаем соль в бинарном виде
     long salt_size = 0;
     unsigned char* salt = OPENSSL_hexstr2buf(hex_salt.c_str(), &salt_size );
     if( !salt || salt_size <= 0 )
     {
          std::cerr << "Salt is invalid";
          return -1;
     }

     uint64_t scrypt_n = 65536;         // объём вычислений
     uint32_t scrypt_r = 8;             // потребление памяти
     uint32_t scrypt_p = 1;             // распараллеливание

     // получаем описание алгоритма
     EVP_KDF* kdf = EVP_KDF_fetch( nullptr, OSSL_KDF_NAME_SCRYPT, nullptr );

     // формируем набор параметров
     OSSL_PARAM params[] =
     {
          OSSL_PARAM_construct_octet_string( OSSL_KDF_PARAM_PASSWORD, ( char* )password.c_str(), password.length() ),
          OSSL_PARAM_construct_octet_string( OSSL_KDF_PARAM_SALT, salt, salt_size ),
          OSSL_PARAM_construct_uint64( OSSL_KDF_PARAM_SCRYPT_N, &scrypt_n ),
          OSSL_PARAM_construct_uint32( OSSL_KDF_PARAM_SCRYPT_R, &scrypt_r ),
          OSSL_PARAM_construct_uint32( OSSL_KDF_PARAM_SCRYPT_P, &scrypt_p ),
          OSSL_PARAM_construct_end()
     };

     // формируем ключ
     EVP_KDF_CTX* ctx = EVP_KDF_CTX_new( kdf );
     unsigned char key[ key_size ];
     EVP_KDF_derive( ctx, key, key_size, params );

     EVP_KDF_CTX_free( ctx );
     EVP_KDF_free( kdf );
     OPENSSL_free( salt );

     // выводим ключ
     for( size_t i = 0; i < key_size; i++ )
     {
          if( i != 0 )
          {
               printf( ":" );
          }
          printf( "%02X", key[ i ] );
     }
     std::cout << std::endl;
     return 0;
}