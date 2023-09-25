#include <openssl/pem.h>
#include <iostream>
#include <fstream>
#include <openssl/core_names.h>

EVP_PKEY* read_private_key( const std::string& path )
{
     FILE* pkey_file = fopen( path.c_str(), "rb" );
     EVP_PKEY* pkey = PEM_read_PrivateKey( pkey_file, nullptr, nullptr, nullptr );
     fclose( pkey_file );
     return pkey;
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
     const std::string private_key_file_name = argv[ 3 ];

     // загружаем закрытый ключ
     EVP_PKEY* pkey = read_private_key( private_key_file_name );
     if( !pkey )
     {
          std::cerr << "Error read private key";
          return -1;
     }

     // создаем контекст для расшифровки
     EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_pkey( nullptr, pkey, nullptr );

     // инициализируем контекст и устанавливаем режим дополнения
     EVP_PKEY_decrypt_init( ctx );
     EVP_PKEY_CTX_set_rsa_padding( ctx, RSA_PKCS1_OAEP_PADDING );

     // создаем массивы данных
     size_t pkey_size = EVP_PKEY_get_size( pkey );
     unsigned char* in_buf = new unsigned char[ pkey_size ];
     unsigned char* out_buf = new unsigned char[ pkey_size ];


     std::ifstream inp_file( input_file_name, std::ios::binary | std::ios::in );
     if( !inp_file.is_open() )
     {
          std::cerr << "Input file open error";
          return -1;
     }

     // читаем данные
     size_t in_nbytes = inp_file.read( reinterpret_cast< char* >( in_buf ), pkey_size ).gcount();

     // расшифровываем данные
     size_t out_nbytes = pkey_size;
     EVP_PKEY_decrypt( ctx, out_buf, &out_nbytes, in_buf, in_nbytes );

     // выводим данные в файл
     std::ofstream out_file( output_file_name, std::ios::binary | std::ios::out );
     if( !out_file.is_open() )
     {
          std::cerr << "Output file open error";
          return -1;
     }
     out_file.write( reinterpret_cast< const char* >( out_buf ), out_nbytes );

     //освобождаем память
     delete[] in_buf;
     delete[] out_buf;
     EVP_PKEY_CTX_free( ctx );
     EVP_PKEY_free( pkey );

     std::cout << "Complete";
     return 0;
}

