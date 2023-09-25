#include <openssl/pem.h>
#include <iostream>
#include <fstream>
#include <openssl/core_names.h>


EVP_PKEY* read_pubkey( const std::string& path )
{
     FILE* file = fopen( path.c_str(), "rb" );
     if( !fopen )
     {
          return nullptr;
     }
     EVP_PKEY* res = PEM_read_PUBKEY( file, nullptr, nullptr, nullptr );
     fclose( file );
     return res;
}

int main( int argc, char* argv[] )
{
     if( argc != 4 )
     {
          std::cerr << "Invalid usage";
          return -1;
     }
     const std::string input_file_name = argv[ 1 ];
     const std::string output_file_name = argv[ 2 ];
     const std::string open_key_file_name = argv[ 3 ];

     // считываем из файла открытый ключ
     EVP_PKEY* pkey = read_pubkey( open_key_file_name );
     if( !pkey )
     {
          std::cerr << "Open public key error";
          return -1;
     }

     // создаем контекст с публичным ключом
     EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey( nullptr, pkey, nullptr );

     //инициализируем контекст и устанавливаем режим дополнения
     // EVP_PKEY_encrypt_init( ctx );
     OSSL_PARAM params[] =
     {
          OSSL_PARAM_construct_utf8_string( OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PKEY_RSA_PAD_MODE_OAEP, 0 ),
          OSSL_PARAM_construct_end()
     };
     EVP_PKEY_encrypt_init_ex( ctx, params );

     std::ifstream in_file( input_file_name, std::ios::binary | std::ios::in );
     if( !in_file.is_open() )
     {
          std::cerr << "Input file open error";
          return -1;
     }

     // читаем данные из входного файла
     size_t pkey_size = EVP_PKEY_get_size( pkey );
     unsigned char* input_buffer = new unsigned char[ pkey_size ];
     unsigned char* output_buffer = new unsigned char[ pkey_size ];
     size_t in_nbytes = in_file.read( reinterpret_cast< char* >(input_buffer), pkey_size ).gcount();

     // шифруем данные
     size_t out_nbytes = pkey_size;
     EVP_PKEY_encrypt( ctx, output_buffer, &out_nbytes, input_buffer, in_nbytes );

     // выполняем запись в файл
     std::ofstream out_file( output_file_name, std::ios::out | std::ios::binary );
     if( !out_file.is_open() )
     {
          std::cerr << "Open output file error";
          return -1;
     }

     out_file.write( reinterpret_cast< const char* >( output_buffer ), out_nbytes );

     // очищаем буферы и объекты
     delete[] output_buffer;
     delete[] input_buffer;
     EVP_PKEY_CTX_free( ctx );
     EVP_PKEY_free( pkey );
     std::cout << "Complete";
     return 0;
}

