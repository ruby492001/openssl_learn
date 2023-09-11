#pragma once

#include "string"

const std::string src_path = "/home/ruby/Project/openssl/proj/data/src.txt";
const std::string dst_path = "/home/ruby/Project/openssl/proj/data/crypted.bin";
const std::string decrypted_path = "/home/ruby/Project/openssl/proj/data/decrypted.txt";
const std::string key = "08108fa01d84c921e5c0f1a79e6a3765";

const size_t iv_size = 12;
const size_t auth_token_size = 16;