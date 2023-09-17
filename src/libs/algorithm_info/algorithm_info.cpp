#include "algorithm_info.h"

#include <map>
#include <openssl/evp.h>

namespace crypt_wrapper
{

std::map< CryptAlgorithm, const EVP_CIPHER* > chippers;

AlgorithmInfo::AlgorithmInfo( crypt_wrapper::CryptAlgorithm algorithm )
{
     switch( algorithm )
     {
          case CA_Aes_256_Gcm:
          {
               init_aes_256_gcm();
               break;
          }
          case CA_Aes_256_Cbc:
          {
               init_aes_256_cbc();
               break;
          }

          default:
          {
               break;
          }
     }
}


bool AlgorithmInfo::is_valid() const
{
     return key_size_ != 0;
}


int AlgorithmInfo::get_key_size() const
{
     return key_size_;
}


int AlgorithmInfo::get_block_size() const
{
     return block_size_;
}


bool AlgorithmInfo::auth_tag_exist() const
{
     return auth_tag_size_ != 0;
}


int AlgorithmInfo::get_auth_tag_size() const
{
     return auth_tag_size_;
}


int AlgorithmInfo::get_iv_size() const
{
     return iv_size_;
}


const EVP_CIPHER* AlgorithmInfo::get_chipper() const
{
     return chipper_;
}


void AlgorithmInfo::init_aes_256_gcm()
{
     if( chippers.count( CA_Aes_256_Gcm ) == 0 )
     {
          chipper_ = chippers.insert( { CA_Aes_256_Gcm, EVP_aes_256_gcm() } ).first->second;
     }
     else
     {
          chipper_ = chippers[ CA_Aes_256_Gcm ];
     }

     key_size_ = EVP_CIPHER_key_length( chipper_ );
     block_size_ = EVP_CIPHER_block_size( chipper_ );
     iv_size_ = EVP_CIPHER_iv_length( chipper_ );
     auth_tag_size_ = 16;
     get_auth_tag_type_ = EVP_CTRL_GCM_GET_TAG;
     set_auth_tag_type_ = EVP_CTRL_GCM_SET_TAG;
}


int AlgorithmInfo::get_auth_tag_type() const
{
     return get_auth_tag_type_;
}


int AlgorithmInfo::set_auth_tag_type() const
{
     return set_auth_tag_type_;
}


void AlgorithmInfo::init_aes_256_cbc()
{
     if( chippers.count( CA_Aes_256_Cbc ) == 0 )
     {
          chipper_ = chippers.insert( { CA_Aes_256_Cbc, EVP_aes_256_cbc() } ).first->second;
     }
     else
     {
          chipper_ = chippers[ CA_Aes_256_Cbc ];
     }
     key_size_ = EVP_CIPHER_key_length( chipper_ );
     block_size_ = EVP_CIPHER_block_size( chipper_ );
     iv_size_ = EVP_CIPHER_iv_length( chipper_ );
     auth_tag_size_ = 0;
}

}