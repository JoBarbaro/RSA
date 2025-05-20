
#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
#include <bitset>
#include <map>
#include <algorithm>

#include <rsa.h>
#include <osrng.h>
#include <base64.h>
#include <files.h>
#include <hex.h>

using namespace CryptoPP;
using namespace std;
using namespace std::chrono;


size_t CountBitDifferences(const string& a, const string& b) {
    size_t count = 0;
    size_t len = min(a.size(), b.size());
    for (size_t i = 0; i < len; ++i) {
        byte diff = a[i] ^ b[i];
        for (int bit = 0; bit < 8; ++bit)
            count += (diff >> bit) & 1;
    }
    return count;
}


double EstimateEntropy(const string& data) {
    map<byte, size_t> freq;
    for (byte c : data)
        freq[c]++;
    double entropy = 0.0;
    for (auto& pair : freq) {
        double p = static_cast<double>(pair.second) / data.size();
        entropy -= p * log2(p);
    }
    return entropy * data.size(); 
}


void print_results_no_key_mode(double enc_time, double dec_time,
    double speed_enc, double speed_dec, const string& recovered,
    const string& plaintext, size_t bit_diff, double entropy)
{
    cout << "Время шифрования: " << enc_time << " микросекунд" << endl
        << "Скорость шифрования: " << fixed << setprecision(2) << speed_enc << " Байт/мкс" << endl
        << "Время дешифрования: " << dec_time << " микросекунд" << endl
        << "Скорость дешифрования: " << fixed << setprecision(2) << speed_dec << " Байт/мкс" << endl
        << "Соответствие текста: " << (recovered == plaintext ? "Да" : "НЕТ!") << endl
        << "----------------------------------------" << endl;
    cout << "Bit differences after 1-bit input change: " << bit_diff << " bits" << endl;
    cout << "Ciphertext entropy: " << fixed << setprecision(4) << entropy << " bits" << endl << endl;
}


void TestRSAEncryption(const string& modeName, unsigned int keySize, const string& plaintext) {
    cout << "\n=== " << modeName << " (key size: " << keySize << " бит) ===" << endl;

    AutoSeededRandomPool rng;

    
    auto start_keygen = high_resolution_clock::now();
    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, keySize);
    RSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);
    auto end_keygen = high_resolution_clock::now();
    auto duration_keygen = duration_cast<microseconds>(end_keygen - start_keygen);
    cout << "Key generation time: " << duration_keygen.count() << " mikroseconds" << endl;

    string ciphertext, recovered;

   
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    size_t maxPlaintextLength = encryptor.FixedMaxPlaintextLength();
    string truncatedText = plaintext.substr(0, maxPlaintextLength);
    string modifiedText = truncatedText;
    modifiedText[0] ^= 0x01; // изменение одного бита

    
    auto start_enc = high_resolution_clock::now();
    StringSource ss(truncatedText, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(ciphertext)
        )
    );
    auto end_enc = high_resolution_clock::now();
    auto duration_enc = duration_cast<microseconds>(end_enc - start_enc).count();

   
    string ciphertext_modified;
    StringSource ss_mod(modifiedText, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(ciphertext_modified)
        )
    );

    
    size_t bitDiff = CountBitDifferences(ciphertext, ciphertext_modified);

    
    auto start_dec = high_resolution_clock::now();
    try {
        RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
        StringSource ss2(ciphertext, true,
            new PK_DecryptorFilter(rng, decryptor,
                new StringSink(recovered)
            )
        );
    }
    catch (const Exception& e) {
        cerr << "Decryption error: " << e.what() << endl;
        return;
    }
    auto end_dec = high_resolution_clock::now();
    auto duration_dec = duration_cast<microseconds>(end_dec - start_dec).count();


    double speed_enc = static_cast<double>(truncatedText.size()) / duration_enc;
    double speed_dec = static_cast<double>(truncatedText.size()) / duration_dec;

    
    double entropy_val = 0.0;
    map<byte, int> freq;
    for (byte b : ciphertext)
        freq[b]++;
    for (auto& p : freq) {
        double prob = static_cast<double>(p.second) / ciphertext.size();
        entropy_val += -prob * log2(prob);
    }
    entropy_val *= ciphertext.size();

    
    print_results_no_key_mode(duration_enc, duration_dec,
        speed_enc, speed_dec, recovered, truncatedText, bitDiff, entropy_val);
}

int main() {
    setlocale(LC_ALL, "Rus");
    vector<string> testMessages = {
        "Короткий текстгг",
        string(16 * 8, 'gf'),
        string(16*12, 'R'),
        string(16*16, 'U'),
        string(18 * 18,'E'),
        //string(256 * 256, 'G'),
        //string(1024 * 1024, 'A'),
        //string(2048 * 2048, 'T'),
        //string(4096 * 4096,'R')
    };

    
    for (const auto& msg : testMessages) {
        cout << "\nТестирование (n бит, " << msg.size() << " байт)" << endl;
        //TestRSAEncryption("RSA_OAEP_SHA_2048", 2048, msg);
        TestRSAEncryption("RSA_OAEP_SHA_3072", 3072, msg);
        //TestRSAEncryption("RSA_OAEP_SHA_4096", 4096, msg);
    }
    return 0;
}
