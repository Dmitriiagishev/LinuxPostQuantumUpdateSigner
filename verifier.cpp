#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// Указатели, которые автоматически освобождают объекты OpenSSL.
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using ContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

// Вывод ошибок OpenSSL.
[[noreturn]]
void openssl_error(const std::string& message)
{
    std::cerr << "OpenSSL: " << message << '\n';
    ERR_print_errors_fp(stderr);

    throw std::runtime_error(
        "ошибка криптографической операции"
    );
}

// Чтение файла в бинарном режиме.
std::vector<unsigned char> read_file(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);

    if (!input) {
        throw std::runtime_error(
            "не удалось открыть файл: " + path.string()
        );
    }

    std::vector<unsigned char> data{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()
    };

    if (input.bad()) {
        throw std::runtime_error(
            "не удалось прочитать файл: " + path.string()
        );
    }

    if (data.empty()) {
        throw std::runtime_error(
            "файл пуст: " + path.string()
        );
    }

    return data;
}

// Загрузка открытого ключа из PEM-файла.
KeyPtr load_public_key(const fs::path& key_path)
{
    BioPtr input(
        BIO_new_file(key_path.c_str(), "rb"),
        BIO_free
    );

    if (!input) {
        openssl_error(
            "не удалось открыть открытый ключ: " +
            key_path.string()
        );
    }

    KeyPtr key(
        PEM_read_bio_PUBKEY(
            input.get(),
            nullptr,
            nullptr,
            nullptr
        ),
        EVP_PKEY_free
    );

    if (!key) {
        openssl_error(
            "не удалось прочитать открытый ключ PEM"
        );
    }

    return key;
}

// Проверка подписи выбранным алгоритмом.
//
// Возвращает:
//   true  — подпись действительна;
//   false — подпись недействительна.
//
// При ошибке чтения ключа или настройки OpenSSL
// выбрасывается исключение.
bool verify_signature(
    const std::string& algorithm,
    EVP_PKEY* key,
    const std::vector<unsigned char>& data,
    const std::vector<unsigned char>& signature
)
{
    // Проверяем, что тип ключа соответствует выбранному алгоритму.
    if (algorithm == "ml-dsa-65") {
        if (EVP_PKEY_is_a(key, "ML-DSA-65") != 1) {
            throw std::runtime_error(
                "ожидается открытый ключ ML-DSA-65"
            );
        }
    }
    else if (algorithm == "ed25519") {
        if (EVP_PKEY_is_a(key, "ED25519") != 1) {
            throw std::runtime_error(
                "ожидается открытый ключ Ed25519"
            );
        }
    }
    else if (algorithm == "rsa4096-pss") {
        if (
            EVP_PKEY_is_a(key, "RSA") != 1 ||
            EVP_PKEY_get_bits(key) != 4096
        ) {
            throw std::runtime_error(
                "ожидается открытый ключ RSA на 4096 бит"
            );
        }
    }
    else {
        throw std::runtime_error(
            "неизвестный алгоритм: " + algorithm
        );
    }

    ContextPtr context(
        EVP_MD_CTX_new(),
        EVP_MD_CTX_free
    );

    if (!context) {
        openssl_error(
            "не удалось создать контекст проверки"
        );
    }

    // Контекст принадлежит context и отдельно не освобождается.
    EVP_PKEY_CTX* pkey_context = nullptr;

    // Для RSA-PSS используется SHA-256.
    // Для ML-DSA и Ed25519 внешний хеш не задаётся.
    const char* digest =
        algorithm == "rsa4096-pss" ? "SHA256" : nullptr;

    if (EVP_DigestVerifyInit_ex(
            context.get(),
            &pkey_context,
            digest,
            nullptr,
            nullptr,
            key,
            nullptr
        ) != 1) {
        openssl_error(
            "не удалось инициализировать проверку"
        );
    }

    if (algorithm == "rsa4096-pss") {
        // Параметры должны совпадать с параметрами подписания.
        if (
            EVP_PKEY_CTX_set_rsa_padding(
                pkey_context,
                RSA_PKCS1_PSS_PADDING
            ) <= 0 ||

            EVP_PKEY_CTX_set_rsa_mgf1_md(
                pkey_context,
                EVP_sha256()
            ) <= 0 ||

            EVP_PKEY_CTX_set_rsa_pss_saltlen(
                pkey_context,
                RSA_PSS_SALTLEN_DIGEST
            ) <= 0
        ) {
            openssl_error(
                "не удалось настроить RSA-PSS"
            );
        }
    }

    const int result = EVP_DigestVerify(
        context.get(),
        signature.data(),
        signature.size(),
        data.data(),
        data.size()
    );

    if (result == 1) {
        return true;
    }

    if (result == 0) {
        return false;
    }

    openssl_error(
        "не удалось выполнить проверку подписи"
    );
}

int main(int argc, char* argv[])
{
    if (argc != 5) {
        std::cerr
            << "Использование: " << argv[0]
            << " <алгоритм> <файл> <подпись> <открытый_ключ.pem>\n"
            << "Алгоритмы: ml-dsa-65, ed25519, rsa4096-pss\n";

        return 2;
    }

    try {
        const std::string algorithm = argv[1];

        const fs::path file_path = argv[2];
        const fs::path signature_path = argv[3];
        const fs::path public_key_path = argv[4];

        auto data = read_file(file_path);
        auto signature = read_file(signature_path);
        auto public_key = load_public_key(public_key_path);

        const bool valid = verify_signature(
            algorithm,
            public_key.get(),
            data,
            signature
        );

        if (!valid) {
            std::cerr
                << "Подпись НЕДЕЙСТВИТЕЛЬНА\n";

            return 1;
        }

        std::cout
            << "Подпись действительна ("
            << algorithm
            << ")\n";

        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "Ошибка: " << error.what() << '\n';
        return 2;
    }
}