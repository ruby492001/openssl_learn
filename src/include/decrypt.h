#pragma once

#include "string"
#include "common_defs.h"
#include "openssl/ssl.h"
#include "openssl/rand.h"
#include "algorithm_info.h"


namespace crypt_wrapper
{

class DecryptWrapper
{
public:
     DecryptWrapper( const AlgorithmInfo& info );
     ~DecryptWrapper();

     void init( const binary_array& iv, const binary_array& key );


     void decrypt_data( const binary_array& inp, binary_array& out );
     void final( const crypt_wrapper::binary_array& auth_tag = crypt_wrapper::binary_array() );

private:
     EVP_CIPHER_CTX* ctx = nullptr;
     const AlgorithmInfo info_;
};

}
