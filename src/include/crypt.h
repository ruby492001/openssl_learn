#pragma once

#include "string"
#include "common_defs.h"
#include "openssl/ssl.h"
#include "openssl/rand.h"
#include "algorithm_info.h"


namespace crypt_wrapper
{

class CryptWrapper
{
public:
     CryptWrapper( const AlgorithmInfo& info );
     ~CryptWrapper();

     void init( const binary_array& key );

     binary_array get_iv() const;
     binary_array get_key() const;
     void crypt_data( const binary_array& inp, binary_array& out );
     binary_array final();
     binary_array get_auth_tag();

private:
     binary_array iv_;
     binary_array key_;
     EVP_CIPHER_CTX* ctx = nullptr;
     const AlgorithmInfo info_;
};

}
