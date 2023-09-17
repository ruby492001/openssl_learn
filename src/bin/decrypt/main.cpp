#include <fstream>
#include <iostream>

#include "decrypt.h"
#include "common_defs.h"


bool read_info( const std::string& path, crypt_wrapper::binary_array& iv, crypt_wrapper::binary_array& auth_token )
{
     std::ifstream info_file( path, std::ios::in | std::ios::binary );
     if( !info_file.is_open() )
     {
          std::cerr << "Open info file error";
          return false;
     }
     // считываем префикс
     crypt_wrapper::info_file_prefix file_info;
     if( info_file.read( reinterpret_cast< char* >( &file_info ), sizeof( file_info ) ).gcount() != sizeof( file_info ) )
     {
          std::cerr << "Prefix read error";
          return false;
     }
     iv.resize( file_info.iv_size );
     auth_token.resize( file_info.auth_token_size );

     if( info_file.read( reinterpret_cast< char* >( iv.data() ), iv.size() ).gcount() != iv.size() )
     {
          std::cerr << "Read IV error";
          return false;
     }

     if( info_file.read( reinterpret_cast< char* >( auth_token.data() ), auth_token.size() ).gcount() != auth_token.size() )
     {
          std::cerr << "Read auth token error";
          return false;
     }
     return true;
}


int main()
{
     // открываем нужные файлы
     std::ifstream crypted_file( default_values::crypted_path, std::ios::in | std::ios::binary );
     std::ofstream out_file( default_values::decrypted_path, std::ios::out | std::ios::binary );

     if( !crypted_file.is_open() )
     {
          std::cerr << "Open crypted file error";
          return -1;
     }
     if( !out_file.is_open() )
     {
          std::cerr << "Open out file error";
          return -1;
     }

     crypt_wrapper::binary_array iv;
     crypt_wrapper::binary_array auth_token;
     // считываем iv и аутентификационный токен из файла

     if( !read_info( default_values::info_path, iv, auth_token ) )
     {
          return -1;
     }


     crypt_wrapper::AlgorithmInfo info( crypt_wrapper::CA_Aes_256_Gcm );
     crypt_wrapper::DecryptWrapper wrapper( info );

     try
     {
          // инитим враппер
          wrapper.init( iv, crypt_wrapper::ba_from_string( default_values::key ) );

          // расшифровываем файл
          crypt_wrapper::binary_array in_buf( 500, 0 );
          crypt_wrapper::binary_array out_buf;
          while( !crypted_file.eof() )
          {
               in_buf.resize( crypted_file.read( reinterpret_cast< char* >( in_buf.data() ), in_buf.size() ).gcount() );
               wrapper.decrypt_data( in_buf, out_buf );
               out_file.write( reinterpret_cast< char* >( out_buf.data() ), out_buf.size() );
          }
          wrapper.final( auth_token );
     }
     catch ( const std::exception& ex )
     {
          std::cerr << ex.what();
          return -1;
     }

     std::cout << "Done!";

     return 0;
}