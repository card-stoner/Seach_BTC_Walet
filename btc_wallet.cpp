#include <iostream>
#include <fstream>
#include <string>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <vector>
#include <cstdlib>
#include <ctime>

using namespace std;

string sha256(const string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.size(), hash);

    char hex_output[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hex_output + i * 2, "%02x", hash[i]);
    }
    return string(hex_output);
}

string hmac_sha512(const string& key, const string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    HMAC(EVP_sha512(), key.c_str(), key.size(), (unsigned char*)data.c_str(), data.size(), hash, &len);

    char hex_output[len * 2 + 1];
    for (unsigned int i = 0; i < len; i++) {
        sprintf(hex_output + i * 2, "%02x", hash[i]);
    }
    return string(hex_output);
}

bool loadWords(const string& filename, vector<string>& words) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Не удалось открыть файл " << filename << endl;
        return false;
    }

    string word;
    while (file >> word) {
        words.push_back(word);
    }

    file.close();
    return !words.empty();
}

string generateMnemonic(const vector<string>& words) {
    string mnemonic;
    for (int i = 0; i < 12; ++i) {
        mnemonic += words[rand() % words.size()] + " ";
    }
    mnemonic.pop_back(); 
    return mnemonic;
}

void displayMnemonicInfo(const string& mnemonic) {
    cout << "Mnemonic: " << mnemonic << endl;

    string seed = hmac_sha512("Bitcoin seed", mnemonic);
    cout << "Seed: " << seed << endl;

    string hash = sha256(seed);
    cout << "SHA256 of Seed: " << hash << endl;

    cout << "---------------------------------" << endl;
}

int main() {
    srand(time(0));

    vector<string> words;
    if (!loadWords("bip.txt", words)) {
        return 1;
    }

    while (true) {
        string mnemonic = generateMnemonic(words);
        displayMnemonicInfo(mnemonic);
    }

    return 0;
}
