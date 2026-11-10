#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>
#include <chrono>

namespace fs = std::filesystem;

// OpenSSL требует освобождать свои объекты специальными функциями.
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using ContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

[[noreturn]]
void openssl_error(const std::string& message){
    std::cerr << "OpenSSL: " << message << '\n';
    ERR_print_errors_fp(stderr);

    throw std::runtime_error(
        "криптографическая операция не выполнена"
    );
}

// Загрузка закрытого ключа из PEM-файла.
KeyPtr load_private_key(const fs::path& key_path){
    BioPtr input(
        BIO_new_file(key_path.c_str(), "rb"),
        BIO_free
    );

    if (!input) {
        openssl_error(
            "не удалось открыть закрытый ключ: " + key_path.string()
        );
    }

    // Если ключ зашифрован паролем, OpenSSL запросит его в терминале.
    KeyPtr key(
        PEM_read_bio_PrivateKey(input.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free
    );

    if (!key) {
        openssl_error("не удалось прочитать закрытый ключ PEM");
    }


    return key;
}

// Чтение пакета в бинарном режиме.
std::vector<unsigned char> read_package(const fs::path& package_path){
    std::ifstream input(package_path, std::ios::binary);

    if (!input) {
        throw std::runtime_error(
            "не удалось открыть пакет: " + package_path.string()
        );
    }

    std::vector<unsigned char> data{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()
    };

    if (input.bad()) {
        throw std::runtime_error(
            "ошибка при чтении пакета: " + package_path.string()
        );
    }

    if (data.empty()) {
        throw std::runtime_error(
            "пакет пуст: " + package_path.string()
        );
    }

    return data;
}

// Создание подписи RSA-4096.
std::vector<unsigned char> sign_package(EVP_PKEY* key, const std::vector<unsigned char>& package){
    if (
        !key ||
        EVP_PKEY_is_a(key, "RSA") != 1 ||
        EVP_PKEY_get_bits(key) != 4096
    ) {
        throw std::runtime_error(
            "ожидается закрытый ключ RSA длиной 4096 бит"
        );
    }

    ContextPtr context(
        EVP_MD_CTX_new(),
        EVP_MD_CTX_free
    );

    if (!context) {
        openssl_error("не удалось создать контекст RSA");
    }

    // Этим контекстом владеет context; отдельно освобождать его не нужно.
    EVP_PKEY_CTX* pkey_context = nullptr;

    // Для RSA-PSS используем SHA-256.
    if (EVP_DigestSignInit_ex(
            context.get(),
            &pkey_context,
            "SHA256",
            nullptr,
            nullptr,
            key,
            nullptr
        ) != 1) {
        openssl_error("не удалось инициализировать RSA-SHA256");
    }

    // Явно задаём параметры RSA-PSS:
    // - режим дополнения PSS;
    // - SHA-256 для MGF1;
    // - длину соли, равную длине хеша.
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
        openssl_error("не удалось настроить RSA-PSS");
    }

    size_t signature_size = 0;

    // Определяем необходимый размер буфера.
    if (EVP_DigestSign(
            context.get(),
            nullptr,
            &signature_size,
            package.data(),
            package.size()
        ) != 1) {
        openssl_error(
            "не удалось определить размер подписи RSA"
        );
    }

    std::vector<unsigned char> signature(signature_size);

    // Создаём подпись.
    if (EVP_DigestSign(
            context.get(),
            signature.data(),
            &signature_size,
            package.data(),
            package.size()
        ) != 1) {
        openssl_error("не удалось создать подпись RSA");
    }

    signature.resize(signature_size);
    return signature;
}

// Запись подписи без перезаписи существующего файла.
void write_signature(const fs::path& output_path, const std::vector<unsigned char>& signature){
    const int fd = open(
        output_path.c_str(),
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
        0644
    );

    if (fd < 0) {
        throw std::runtime_error(
            "не удалось создать файл подписи " +
            output_path.string() +
            ": " +
            std::strerror(errno)
        );
    }

    size_t written = 0;
    int error = 0;

    while (written < signature.size()) {
        const ssize_t result = write(
            fd,
            signature.data() + written,
            signature.size() - written
        );

        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }

            error = errno;
            break;
        }

        if (result == 0) {
            error = EIO;
            break;
        }

        written += static_cast<size_t>(result);
    }

    if (close(fd) != 0 && error == 0) {
        error = errno;
    }

    if (error != 0) {
        // Удаляем только неполный файл, созданный этим запуском.
        unlink(output_path.c_str());

        throw std::runtime_error(
            "ошибка записи подписи: " +
            std::string(std::strerror(error))
        );
    }
}

int main(int argc, char* argv[]){
    if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        std::cout
            << "Использование: " << argv[0]
            << " <пакет> <закрытый_ключ.pem> [файл_подписи]\n"
            << "По умолчанию подпись сохраняется как <пакет>.ed25519\n";

        return 0;
    }

    if (argc != 3) {
        std::cerr
            << "Использование: " << argv[0]
            << " <пакет> <закрытый_ключ.pem>\n";

        return 2;
    }

    try {
        const fs::path package_path(argv[1]);
        const fs::path key_path(argv[2]);

        const fs::path output_path = fs::path(package_path.string() + ".rsa4096");

        auto start = std::chrono::steady_clock::now();
        auto key = load_private_key(key_path);
        std::cout << "Ключ загружен за " << std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count() << " μс\n";
        start = std::chrono::steady_clock::now();
        auto package = read_package(package_path);
        auto signature = sign_package(key.get(), package);
        std::cout << "Подпись создана за " << std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count() << " μс\n"; 

        write_signature(output_path, signature);

        std::cout
            << "Пакет: " << package_path << '\n'
            << "Алгоритм: RSA-4096\n"
            << "Подпись: " << output_path << '\n'
            << "Размер подписи: " << signature.size() << " байт\n";

        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "Ошибка: " << error.what() << '\n';
        return 1;
    }
}