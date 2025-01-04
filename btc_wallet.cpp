#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <array>
#include <memory>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

using namespace std;

string sha256(const string& data) {
    if (data.empty()) {
        throw invalid_argument("Input data is empty");
    }

    array<unsigned char, SHA256_DIGEST_LENGTH> hash;
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash.data());

    char hex_output[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hex_output + i * 2, "%02x", hash[i]);
    }
    return string(hex_output);
}

string hmac_sha512(const string& key, const string& data) 
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    HMAC(EVP_sha512(), key.c_str(), key.size(), reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), hash, &len);

    char hex_output[len * 2 + 1];
    for (unsigned int i = 0; i < len; ++i)
    {
        sprintf(hex_output + i * 2, "%02x", hash[i]);
    }
    return string(hex_output);
}

bool loadWords(const string& filename, vector<string>& words) 
{
    ifstream file(filename);
    if (!file.is_open()) 
    {
        cerr << "Не удалось открыть файл " << filename << endl;
        return false;
    }

    string word;
    while (file >> word) 
    {
        words.push_back(word);
    }
    return !words.empty();
}

string generateMnemonic(const vector<string>& words) 
{
    random_device rd;  
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, words.size() - 1); 

    string mnemonic;
    for (int i = 0; i < 12; ++i) 
    {
        mnemonic += words[dis(gen)] + " ";
    }
    mnemonic.pop_back(); 
    return mnemonic;
}

string generatePrivateKey(const string& seed) 
{
    return sha256(seed);
}

string generatePublicKey(const string& privateKeyHex) 
{
    BIGNUM* privateKeyBN = BN_new();
    BN_hex2bn(&privateKeyBN, privateKeyHex.c_str());

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    EC_POINT* publicKeyPoint = EC_POINT_new(group);

    EC_POINT_mul(group, publicKeyPoint, privateKeyBN, nullptr, nullptr, nullptr);

    char* publicKeyHex = EC_POINT_point2hex(group, publicKeyPoint, POINT_CONVERSION_UNCOMPRESSED, nullptr);

    string publicKey(publicKeyHex);

    BN_free(privateKeyBN);
    EC_GROUP_free(group);
    EC_POINT_free(publicKeyPoint);
    OPENSSL_free(publicKeyHex);

    return publicKey;
}

string generateBitcoinAddress(const string& publicKeyHex) 
{
    string sha256Hash = sha256(publicKeyHex);

    unsigned char ripemdHash[RIPEMD160_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_ripemd160();

    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, sha256Hash.c_str(), sha256Hash.size());
    EVP_DigestFinal_ex(mdctx, ripemdHash, nullptr);
    EVP_MD_CTX_free(mdctx);

    vector<unsigned char> addressBytes;
    addressBytes.push_back(0x00);
    addressBytes.insert(addressBytes.end(), ripemdHash, ripemdHash + RIPEMD160_DIGEST_LENGTH);

    string checksumHash = sha256(string(addressBytes.begin(), addressBytes.end()));
    checksumHash = sha256(checksumHash);

    addressBytes.insert(addressBytes.end(), checksumHash.begin(), checksumHash.begin() + 4);

    const char* base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    string base58Address;
    BIGNUM* num = BN_new();
    BN_bin2bn(addressBytes.data(), addressBytes.size(), num);

    while (BN_is_zero(num) == 0) 
    {
        int remainder = BN_div_word(num, 58);
        base58Address = base58Chars[remainder] + base58Address;
    }

    BN_free(num);

    return base58Address;
}

void writeToFile(const string& filename, const string& mnemonic, const string& seed, const string& hash, const string& privateKey, const string& publicKey, const string& bitcoinAddress) 
{
    ofstream outFile(filename, ios::app); 
    if (!outFile.is_open()) 
    {
        cerr << "Не удалось открыть файл для записи: " << filename << endl;
        return;
    }

    outFile << "Mnemonic: " << mnemonic << endl;
    outFile << "Seed: " << seed << endl;
    outFile << "SHA256 of Seed: " << hash << endl;
    outFile << "Private Key: " << privateKey << endl;
    outFile << "Public Key: " << publicKey << endl;
    outFile << "Bitcoin Address: " << bitcoinAddress << endl;
    outFile << "<------------------------>" << endl;

    outFile.close();
}

void displayMnemonicInfo() {
    vector<string> words;
    if (!loadWords("bip.txt", words)) {
        cerr << "Не удалось загрузить слова из файла." << endl;
        return;
    }

    const string outputFilename = "wallets.txt";

    while (true) {
        string mnemonic = generateMnemonic(words);
        cout << "Mnemonic: " << mnemonic << endl;

        string seed = hmac_sha512("Bitcoin seed", mnemonic);
        cout << "Seed: " << seed << endl;

        string hash = sha256(seed);
        cout << "SHA256 of Seed: " << hash << endl;

        string privateKey = generatePrivateKey(seed);
        cout << "Private Key: " << privateKey << endl;

        string publicKey = generatePublicKey(privateKey);
        cout << "Public Key: " << publicKey << endl;

        string bitcoinAddress = generateBitcoinAddress(publicKey);
        cout << "Bitcoin Address: " << bitcoinAddress << endl;

        cout << "<------------------------>" << endl;

        writeToFile(outputFilename, mnemonic, seed, hash, privateKey, publicKey, bitcoinAddress);
    }
}

int main() {
    displayMnemonicInfo();
}