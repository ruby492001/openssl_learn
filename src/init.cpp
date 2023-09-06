#include "openssl/ssl.h"

#include "iostream"

int main()
{
     std::cout << "Инициализируем OpenSSL" << std::endl;
     OPENSSL_init_ssl( 0, nullptr );
     std::cout << "Очищаем" << std::endl;
     OPENSSL_cleanup();
     std::cout << "Готово!" << std::endl;
     return 0;
}