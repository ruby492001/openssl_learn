#include "decrypt.h"
#include "stdexcept"
#include "iostream"

namespace crypt_wrapper
{

DecryptWrapper::DecryptWrapper( const AlgorithmInfo& info )
:info_( info )
{
}


DecryptWrapper::~DecryptWrapper()
{
     if( ctx )
     {
          EVP_CIPHER_CTX_free( ctx );
          ctx = nullptr;
     }
}


void DecryptWrapper::init( const binary_array& iv, const binary_array& key )
{
     if( ctx )
     {
          throw std::runtime_error( "Already init" );
     }
     if( !info_.is_valid() )
     {
          throw std::runtime_error( "Info is invalid" );
     }

     if( key.size() != info_.get_key_size() )
     {
          throw std::runtime_error( "Key size is invalid" );
     }

     if( iv.size() != info_.get_iv_size() )
     {
          throw std::runtime_error( "IV size is invalid" );
     }

     ctx = EVP_CIPHER_CTX_new();
     if( !ctx )
     {
          throw std::bad_alloc();
     }

     if( 1 != EVP_DecryptInit( ctx, info_.get_chipper(), key.data(), iv.data() ) )
     {
          EVP_CIPHER_CTX_free( ctx );
          ctx = nullptr;
          throw std::runtime_error( "EVP_DecryptInit error" );
     }
}


void DecryptWrapper::decrypt_data( const binary_array& inp, binary_array& out )
{
     if( !ctx )
     {
          throw std::runtime_error( "Not inited" );
     }

     out.resize( inp.size() + info_.get_block_size() );
     int res_length = 0;
     if( 1 != EVP_DecryptUpdate( ctx, &out[ 0 ], &res_length, inp.data(), inp.size() ) )
     {
          throw std::runtime_error( "Decrypt update error" );
     }
     out.resize( res_length );
}


binary_array DecryptWrapper::final( const binary_array& auth_tag )
{
     if( !ctx )
     {
          throw std::runtime_error( "Not inited" );
     }

     if( auth_tag.empty() && info_.auth_tag_exist() )
     {
          throw std::runtime_error( "Auth tag not specified" );
     }

     if( auth_tag.size() != info_.get_auth_tag_size() )
     {
          throw std::runtime_error( "Auth tag invalid size" );
     }

     binary_array tag = auth_tag;
     if( !tag.empty() )
     {
          if( 1 != EVP_CIPHER_CTX_ctrl( ctx, info_.set_auth_tag_type(), tag.size(), static_cast< void* >( tag.data() ) ) )
          {
               throw std::runtime_error( "EVP_CIPHER_CTX_ctrl error" );
          }
     }

     binary_array res( info_.get_block_size(), 0 );
     int size = res.size();
     if( 1 != EVP_DecryptFinal( ctx, res.data(), &size ) )
     {
          throw std::runtime_error( "EVP_DecryptFinal error" );
     }
     res.resize( size );
     return res;
}
}