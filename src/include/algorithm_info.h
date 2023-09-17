#pragma once

#include <cstddef>
#include <openssl/ossl_typ.h>

namespace crypt_wrapper
{

enum CryptAlgorithm
{
     CA_Undefined,
     CA_Aes_256_Gcm
};


class AlgorithmInfo
{
public:
     AlgorithmInfo( CryptAlgorithm algorithm );
     bool is_valid() const;
     int get_key_size() const;
     int get_block_size() const;

     bool auth_tag_exist() const;
     int get_auth_tag_size() const;
     int get_auth_tag_type() const;
     int set_auth_tag_type() const;

     int get_iv_size() const;
     const EVP_CIPHER* get_chipper() const;
private:
     void init_aes_256_gcm();

private:
     int key_size_ = 0;
     int block_size_ = 0;
     int auth_tag_size_ = 0;
     int iv_size_ = 0;
     const EVP_CIPHER* chipper_ = nullptr;
     int get_auth_tag_type_ = 0;
     int set_auth_tag_type_ = 0;
};

}