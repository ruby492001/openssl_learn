#include <fstream>
#include <iostream>

#include "common_defs.h"
#include "crypt.h"


int main()
{
     // открываем входной и выходные файлы, начинаем шифрование

     std::ifstream inp_file( default_values::src_path, std::ios::in | std::ios::binary );
     std::ofstream out_file( default_values::crypted_path, std::ios::out | std::ios::binary );
     std::ofstream info_file( default_values::info_path, std::ios::out | std::ios::binary );

     if( !inp_file.is_open() )
     {
          std::cerr << "Open input file error";
          return -1;
     }
     if( !out_file.is_open() )
     {
          std::cerr << "Open output file error";
          return -1;
     }
     if( !info_file.is_open() )
     {
          std::cerr << "Open info file error";
          return -1;
     }

     crypt_wrapper::AlgorithmInfo alg( crypt_wrapper::CA_Aes_256_Cbc );
     crypt_wrapper::CryptWrapper wrapper( alg );

     try
     {
          wrapper.init( crypt_wrapper::ba_from_string( default_values::key ) );
          crypt_wrapper::binary_array inp_arr( alg.get_block_size(), 0 );
          crypt_wrapper::binary_array out_arr;

          // шифруем файл
          while( !inp_file.eof() )
          {
               inp_arr.resize( inp_file.read( reinterpret_cast< char* >( inp_arr.data() ), inp_arr.size() ).gcount() );
               wrapper.crypt_data( inp_arr, out_arr );
               out_file.write( reinterpret_cast< const char* >( out_arr.data() ), out_arr.size() );
          }
          // записываем дополнение до целого количества блоков
          out_arr = wrapper.final();
          out_file.write( reinterpret_cast< const char* >( out_arr.data() ), out_arr.size() );


          crypt_wrapper::binary_array iv = wrapper.get_iv();
          crypt_wrapper::binary_array auth_tag = wrapper.get_auth_tag();

          crypt_wrapper::info_file_prefix file_prefix;
          file_prefix.iv_size = iv.size();
          file_prefix.auth_token_size = auth_tag.size();

          info_file.write( ( char* )( &file_prefix ), sizeof( file_prefix ) );

          info_file.write( reinterpret_cast< const char* >( iv.data() ), iv.size() );
          info_file.write( reinterpret_cast< const char* >( auth_tag.data() ), auth_tag.size() );
     }
     catch( const std::exception& ex)
     {
          std::cerr << ex.what();
          return -1;
     }

     std::cout << "Done!";

     return 0;
}