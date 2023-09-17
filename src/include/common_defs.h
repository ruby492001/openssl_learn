#pragma once

#include <cstring>
#include <vector>

namespace crypt_wrapper
{
using binary_array = std::vector< unsigned char >;


struct info_file_prefix
{
     char iv_size = 0;
     char auth_token_size = 0;
};


static binary_array ba_from_string( const std::string& str )
{
     binary_array tmp;
     tmp.resize( str.size() );
     memcpy( &tmp[ 0 ], str.c_str(), str.size() );
     return tmp;
}

}


namespace default_values
{
const std::string src_path = "../../../../data/src.bin";
const std::string crypted_path = "../../../../data/crypted.bin";
const std::string decrypted_path = "../../../../data/decrypted.bin";
const std::string info_path = "../../../../data/meta_info.bin";
const std::string key = "08108fa01d84c921e5c0f1a79e6a3765";
}