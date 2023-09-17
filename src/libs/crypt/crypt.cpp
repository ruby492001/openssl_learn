#include <cstring>
#include "crypt.h"
#include "stdexcept"


namespace crypt_wrapper
{


CryptWrapper::CryptWrapper( const AlgorithmInfo& info )
:info_( info )
{
}


CryptWrapper::~CryptWrapper()
{
     if( ctx )
     {
          EVP_CIPHER_CTX_free( ctx );
          ctx = nullptr;
     }
}


void CryptWrapper::init( const binary_array& key )
{
     if( ctx )
     {
          throw std::runtime_error( "Already init" );
     }
     if( !info_.is_valid() )
     {
          throw std::runtime_error( "Info is invalid" );
     }

     key_ = key;
     if( key.size() != info_.get_key_size() )
     {
          throw std::runtime_error( "Key size is invalid" );
     }

     iv_.resize( info_.get_iv_size() );
     if( 1 != RAND_bytes( &iv_[ 0 ], info_.get_iv_size() ) )
     {
          throw std::runtime_error( "Rand bytes error" );
     }

     ctx = EVP_CIPHER_CTX_new();
     if( !ctx )
     {
          throw std::bad_alloc();
     }

     if( 1 != EVP_EncryptInit( ctx, info_.get_chipper(), key_.data(), iv_.data() ) )
     {
          EVP_CIPHER_CTX_free( ctx );
          ctx = nullptr;
          throw std::runtime_error( "EVP_EncryptInit error" );
     }
}


binary_array CryptWrapper::get_iv() const
{
     return iv_;
}


binary_array CryptWrapper::get_key() const
{
     return key_;
}


void CryptWrapper::crypt_data( const binary_array& inp, binary_array& out )
{
     if( !ctx )
     {
          throw std::runtime_error( "Not inited" );
     }
     out.resize( inp.size() + info_.get_block_size() );
     int res_length = 0;
     if( 1 != EVP_EncryptUpdate( ctx, &out[ 0 ], &res_length, inp.data(), inp.size() ) )
     {
          throw std::runtime_error( "EVP_EncryptUpdate error" );
     }
     out.resize( res_length );
}


binary_array CryptWrapper::final()
{
     if( !ctx )
     {
          throw std::runtime_error( "Not inited" );
     }
     binary_array res;
     res.resize( info_.get_block_size() );
     int res_length = res.size();
     if( 1 != EVP_EncryptFinal( ctx, &res[ 0 ], &res_length ) )
     {
          throw std::runtime_error( "EVP_EncryptFinal error" );
     }
     res.resize( res_length );
     return res;
}


binary_array CryptWrapper::get_auth_tag()
{
     if( !ctx )
     {
          throw std::runtime_error( "Not inited" );
     }
     if( !info_.auth_tag_exist() )
     {
          return {};
     }
     binary_array res;
     res.resize( info_.get_auth_tag_size() );
     if( 1 != EVP_CIPHER_CTX_ctrl( ctx, info_.get_auth_tag_type(), info_.get_auth_tag_size(), &res[ 0 ] ) )
     {
          throw std::runtime_error( "EVP_CIPHER_CTX_ctrl error" );
     }
     return res;
}

}