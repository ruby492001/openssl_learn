#include "openssl/ssl.h"
#include "openssl/core_names.h"
#include <openssl/params.h>
#include <fstream>
#include "boost/algorithm/hex.hpp"

#include "iostream"

const size_t key_size = 64;
const size_t max_hmac_size = 1024;

// параметры в контексте вычисления MAC
// указываем, что отим использовать функцию хеширования SHA-256 в качестве базовой функции вычисления хеш-значения
OSSL_PARAM params[] =
{
     OSSL_PARAM_construct_utf8_string( OSSL_MAC_PARAM_DIGEST, OSSL_DIGEST_NAME_SHA3_512, 0 ),
     OSSL_PARAM_construct_end()
};

int main( int argc, char* argv[] )
{
     // получаем параметры из аргументов
     if( argc != 3 )
     {
          std::cerr << "Invalid usage";
          return -1;
     }
     const std::string path = argv[ 1 ];
     unsigned char key[ key_size ];
     std::string hash = boost::algorithm::unhex( std::string( argv[ 2 ] ) );
     if( hash.size() != sizeof( key ) )
     {
          std::cerr << "Invalid key";
          return -1;
     }
     std::copy( hash.begin(), hash.end(), key );

     // получаем описание алгоритма
     EVP_MAC* mac = EVP_MAC_fetch( nullptr, OSSL_MAC_NAME_HMAC, nullptr );

     EVP_MAC_CTX* ctx = EVP_MAC_CTX_new( mac );
     EVP_MAC_init( ctx, key, key_size, params );

     // считаем HMAC файла
     std::ifstream in_file( path, std::ios::binary | std::ios::in );
     if( !in_file.is_open() )
     {
          std::cerr << "Error open file: " << path;
          return -1;
     }

     const size_t buffer_size = 1024;
     char buffer[ buffer_size ];
     while( !in_file.eof() )
     {
          size_t read_count = in_file.read( buffer, buffer_size ).gcount();
          EVP_MAC_update( ctx, reinterpret_cast< const unsigned char* >( buffer ), read_count );
     }

     unsigned char hmac[ max_hmac_size ];
     size_t out_bytes = 0;

     // получаем hmac
     EVP_MAC_final( ctx, hmac, &out_bytes, max_hmac_size );

     // освобождаем ресурсы
     EVP_MAC_CTX_free( ctx );
     EVP_MAC_free( mac );

     std::string res;
     res.resize( out_bytes * 2 + 1 );
     boost::algorithm::hex_lower( hmac, hmac + out_bytes, res.begin() );
     std::cout << "Result HMAC: " << res << std::endl;
     return 0;
}