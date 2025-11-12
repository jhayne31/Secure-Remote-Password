// Interactive SRP client that computes x, k, g^b, u, shared key, and M1, M2 verification values.
// Compile: g++ -std=c++17 SRP.cpp -lssl -lcrypto -O2 -o srp
// Usage: ./srp

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <iomanip>

using Bytes = std::vector<unsigned char>;

Bytes hex_to_bytes(const std::string &hex) {
    std::string h = hex;
    if (h.size() % 2) h = "0" + h;
    Bytes out;
    out.reserve(h.size()/2);
    for (size_t i = 0; i < h.size(); i += 2) {
        unsigned int byte = 0;
        std::istringstream iss(h.substr(i,2));
        iss >> std::hex >> byte;
        out.push_back(static_cast<unsigned char>(byte));
    }
    return out;
}

Bytes bn_to_bytes_min(const BIGNUM *bn) {
    int len = BN_num_bytes(bn);
    if (len <= 0) return Bytes(); // should not happen
    Bytes out(len);
    BN_bn2bin(bn, out.data()); // minimal big-endian
    return out;
}

BIGNUM* bytes_to_bn(const Bytes &b) {
    return BN_bin2bn(b.data(), (int)b.size(), NULL);
}

std::string bn_to_decstr(const BIGNUM *bn) {
    char *s = BN_bn2dec(bn);
    std::string ret(s ? s : "");
    if (s) OPENSSL_free(s);
    return ret;
}

Bytes sha256_concat(const std::vector<Bytes> &parts) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    for (const auto &p : parts) {
        if (!p.empty()) SHA256_Update(&ctx, p.data(), p.size());
    }
    Bytes out(SHA256_DIGEST_LENGTH);
    SHA256_Final(out.data(), &ctx);
    return out;
}

BIGNUM* sha256_bn(const std::vector<Bytes> &parts) {
    Bytes h = sha256_concat(parts);
    return bytes_to_bn(h);
}

BIGNUM* gen_private_a(int bits) {
    int bytes = bits / 8;
    Bytes rnd(bytes);
    if (RAND_bytes(rnd.data(), bytes) != 1) {
        std::cerr << "RAND_bytes failed\n";
        exit(1);
    }
    return bytes_to_bn(rnd);
}

std::string bytes_to_hex_lower(const Bytes &b) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : b) oss << std::setw(2) << (int)c;
    return oss.str();
}

int main() {
    OPENSSL_init_crypto(0, NULL);
    BN_CTX *ctx = BN_CTX_new();

    // DH parameters (p and g) - p from your assignment, g = 5
    const std::string p_dec =
    "233000556327543348946447470779219175150430130236907257523476085501968599658761371268535640963004707302492862642690597042148035540759198167263992070601617519279204228564031769469422146187139698860509698350226540759311033166697559129871348428777658832731699421786638279199926610332604408923157248859637890960407";
    const unsigned long g_word = 5;

    BIGNUM *p = BN_new();
    if (!BN_dec2bn(&p, p_dec.c_str())) { std::cerr << "BN_dec2bn p failed\n"; return 1; }
    BIGNUM *g = BN_new();
    BN_set_word(g, g_word);

    // generate private a and compute A = g^a mod p
    BIGNUM *a = gen_private_a(256);
    if (!a) { std::cerr << "gen_private_a failed\n"; return 1; }

    BIGNUM *A = BN_new();
    if (!BN_mod_exp(A, g, a, p, ctx)) { std::cerr << "BN_mod_exp A failed\n"; return 1; }

    std::cout << "Client public g^a (A) (decimal):\n" << bn_to_decstr(A) << "\n\n";

    // Prompt for inputs
    std::string username, password, salt_hex, B_dec_str;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    std::cout << "Enter password: ";
    std::getline(std::cin, password);
    std::cout << "Enter salt (hex): ";
    std::getline(std::cin, salt_hex);
    std::cout << "Enter server public B (decimal): ";
    std::getline(std::cin, B_dec_str);

    // parse values
    Bytes salt = hex_to_bytes(salt_hex);

    BIGNUM *B = BN_new();
    if (!BN_dec2bn(&B, B_dec_str.c_str())) { std::cerr << "BN_dec2bn B failed\n"; return 1; }

    const int iterations = 1000;

    // compute x = H(salt || password) iterated iterations times
    Bytes pw_bytes(password.begin(), password.end());
    Bytes h = sha256_concat({salt, pw_bytes});
    for (int i = 1; i < iterations; ++i) {
        h = sha256_concat({h});
    }
    BIGNUM *x = bytes_to_bn(h);

    // compute k = H(p || g)
    // use minimal big-endian bytes for p and g
    Bytes p_bytes = bn_to_bytes_min(p);
    // convert g to BN then to minimal bytes
    BIGNUM *g_bn = BN_new(); BN_set_word(g_bn, g_word);
    Bytes g_bytes = bn_to_bytes_min(g_bn);
    BIGNUM *k = sha256_bn({p_bytes, g_bytes});

    // compute v = g^x mod p
    BIGNUM *v = BN_new();
    if (!BN_mod_exp(v, g, x, p, ctx)) { std::cerr << "BN_mod_exp v failed\n"; return 1; }

    // compute g^b = (B - k*v) mod p
    BIGNUM *kv = BN_new();
    if (!BN_mod_mul(kv, k, v, p, ctx)) { std::cerr << "BN_mod_mul kv failed\n"; return 1; }

    BIGNUM *g_pow_b = BN_new();
    if (!BN_mod_sub(g_pow_b, B, kv, p, ctx)) { std::cerr << "BN_mod_sub g^b failed\n"; return 1; }
    if (BN_is_negative(g_pow_b)) BN_add(g_pow_b, g_pow_b, p);

    // compute u = H(g^a || g^b) using minimal big-endian encodings (NO padding)
    Bytes A_min = bn_to_bytes_min(A);
    Bytes gb_min = bn_to_bytes_min(g_pow_b);
    BIGNUM *u = sha256_bn({A_min, gb_min});

    // compute shared key S = (g^b)^(a + u*x) mod p
    BIGNUM *ux = BN_new();
    if (!BN_mul(ux, u, x, ctx)) { std::cerr << "BN_mul ux failed\n"; return 1; }
    BIGNUM *exp = BN_new();
    if (!BN_add(exp, a, ux)) { std::cerr << "BN_add exp failed\n"; return 1; }

    BIGNUM *S = BN_new();
    if (!BN_mod_exp(S, g_pow_b, exp, p, ctx)) { std::cerr << "BN_mod_exp S failed\n"; return 1; }

    // Print results (decimal)
    std::cout << "\nSubmission Outputs\n\n";
    std::cout << "Password hash as an integer (x = H(salt || password)^" << iterations << "):\n" << bn_to_decstr(x) << "\n\n";
    std::cout << "k = H(p || g) as an integer:\n" << bn_to_decstr(k) << "\n\n";
    std::cout << "g^b ≡ B - k·v (mod p) as an integer (labelled \"g^b\"):\n" << bn_to_decstr(g_pow_b) << "\n\n";
    std::cout << "u = H(g^a || g^b) as an integer (labelled \"u\"):\n" << bn_to_decstr(u) << "\n\n";
    std::cout << "Shared key as an integer (S):\n" << bn_to_decstr(S) << "\n\n";

    // Compute M1 and M2 using S (raw big-endian bytes)
    // H(p), H(g), H(username)
    Bytes H_p = sha256_concat({p_bytes});
    Bytes H_g = sha256_concat({g_bytes});
    Bytes H_user = sha256_concat({Bytes(username.begin(), username.end())});

    // H(p) XOR H(g)
    Bytes Hxor(SHA256_DIGEST_LENGTH);
    for (size_t i = 0; i < Hxor.size(); ++i) Hxor[i] = H_p[i] ^ H_g[i];

    Bytes S_bytes = bn_to_bytes_min(S);

    // Build M1 = H(H(p) xor H(g) || H(username) || salt || g^a || g^b || S)
    Bytes M1 = sha256_concat({ Hxor, H_user, salt, A_min, gb_min, S_bytes });

    // M2 = H(g^a || M1 || S)
    Bytes M2 = sha256_concat({ A_min, M1, S_bytes });

    // Print M1 & M2 as HEX
    std::cout << "Client verification M1 (hex):\n" << bytes_to_hex_lower(M1) << "\n\n";
    std::cout << "Server verification M2 (hex):\n" << bytes_to_hex_lower(M2) << "\n\n";


    // cleanup
    BN_free(p); BN_free(g); BN_free(g_bn); BN_free(a); BN_free(A); BN_free(B);
    BN_free(x); BN_free(k); BN_free(v); BN_free(kv); BN_free(g_pow_b);
    BN_free(u); BN_free(ux); BN_free(exp); BN_free(S);
    BN_CTX_free(ctx);

    return 0;
}
