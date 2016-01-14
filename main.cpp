#pragma warning(disable : 4996)

#include <string.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <streambuf>
#include <iterator>
#include <algorithm>
#include <WinCryptEx.h>
//#include <xmlsec1/xmlsec/xmldsig.h>
//#include <CSP_WinError.h>

using namespace std;

void dump(unsigned char* source, size_t length)
{
    for(size_t i = 0; i < length; i++)
        printf("%x ", source[i]);
    cout << endl;
}

int error(string message)
{
    cerr /*<< "error " << GetLastError() << ": "*/ << message << endl;
    return -1;
}

class Certificate
{
    public:
        Certificate(string pem)
        {
            vector<unsigned char> der(2048);
            DWORD length = der.size();
            if(CryptStringToBinary(pem.c_str(), 0, CRYPT_STRING_BASE64_ANY, &der[0], &length, NULL, NULL))
            {
                der.resize(length);
                assign(der);
            }
            else
                error("CryptStringToBinary() failed");
        }

        Certificate(vector<unsigned char> der)
        {
            assign(der);
        }

        ~Certificate()
        {
            if(context)
                CertFreeCertificateContext(context);
        }

        PCCERT_CONTEXT getContext()
        {
            return context;
        }

        bool isValid()
        {
            /*CertVerifyCertificateChainPolicy()
            CertVerifyCRLTimeValidity
            CertVerifyRevocation
            CertVerifySubjectCertificateContext
            CertVerifyValidityNesting*/

            if(context != 0) // format valid
            {
                PCCERT_CHAIN_CONTEXT pChainContext = 0;
                CERT_CHAIN_PARA pChainPara;
                memset(&pChainPara, 0, sizeof(pChainPara));
                pChainPara.cbSize = sizeof(pChainPara);
                // TODO pChainPara init
                bool isChainValid = CertGetCertificateChain(NULL, context, NULL, NULL, &pChainPara, CERT_CHAIN_REVOCATION_CHECK_CHAIN, NULL, &pChainContext);
                CertFreeCertificateChain(pChainContext);

                return isChainValid;
            }

            return false;
        }

    private:
        PCCERT_CONTEXT context = 0;

        void assign(vector<unsigned char> &der)
        {
            if(context = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, &der[0], der.size()))
                ;
            else
                error("CertCreateCertificateContext() failed");
        }
};

// TODO signature class
// TODO hash class

HCRYPTHASH makeCryptHash(string data, HCRYPTPROV hProv)
{
    HCRYPTHASH hHash = 0;
    if(CryptCreateHash(hProv, CALG_GR3411, 0, 0, &hHash))
        if(CryptHashData(hHash, (BYTE*)data.c_str(), data.size(), 0))
            return hHash;
        else
            error("CryptHashData() failed");
    else
        error("CryptCreateHash() failed");

    CryptDestroyHash(hHash);
    return 0;
}

bool hashFromCryptHash(HCRYPTHASH hHash, vector<unsigned char> &hash)
{
    DWORD cbHash = 0;
    DWORD cb = sizeof(cbHash);

    if(CryptGetHashParam(hHash, HP_HASHSIZE, (LPBYTE)&cbHash, &cb, 0))
    {
        hash.resize(cbHash);

        if(CryptGetHashParam(hHash, HP_HASHVAL, &hash[0], &cbHash, 0))
            return true;
        else
            error("CryptGetHashParam() failed");
    }
    else
        error("CryptGetHashParam() failed");

    return false;
}

vector<unsigned char> base64toBinary(string base64)
{
    vector<unsigned char> binary(0);

    DWORD length = 0;
    if(CryptStringToBinary(base64.c_str(), 0, CRYPT_STRING_BASE64, NULL, &length, NULL, NULL))
    {
        binary.resize(length);
        if(!CryptStringToBinary(base64.c_str(), 0, CRYPT_STRING_BASE64, &binary[0], &length, NULL, NULL))
            binary.clear();
    }

    return binary;
}

bool checkHash(string data, vector<unsigned char> hash, HCRYPTPROV hProv)
{
    HCRYPTHASH hHash = makeCryptHash(data, hProv);
    if(hHash)
    {
        bool isValid = false;
        vector<unsigned char> temp;
        if(hashFromCryptHash(hHash, temp))
            isValid = temp == hash;
        CryptDestroyHash(hHash);
        return isValid;
    }
    else
        return false;
}

HCRYPTKEY importKey(Certificate x509, HCRYPTPROV hProv) // TODO shaded certificate context
{
    HCRYPTKEY hPubKey = 0;
    if(CryptImportPublicKeyInfo(hProv, x509.getContext()->dwCertEncodingType, &x509.getContext()->pCertInfo->SubjectPublicKeyInfo, &hPubKey))
        return hPubKey;
    else
        error("CryptImportPublicKeyInfo() failed");

    if(hPubKey)
        CryptDestroyKey(hPubKey);

    return 0;
}

bool checkSignature(string data, vector<unsigned char> signature, Certificate x509, HCRYPTPROV hProv)
{
    bool isValid = false;

    HCRYPTKEY hPubKey = importKey(x509, hProv);
    if(hPubKey)
    {
        HCRYPTHASH hHash = makeCryptHash(data, hProv);
        if(hHash)
        {
            reverse(signature.begin(), signature.end());
            isValid = CryptVerifySignature(hHash, &signature[0], signature.size(), hPubKey, NULL, 0);

            CryptDestroyHash(hHash);
        }
        else
            error("Can't make hash of signature info");

        CryptDestroyKey(hPubKey);
    }
    else
        error("Can't import public key from certificate");

    return isValid;
}

string loadEntireFile(string name)
{
    ifstream file(name);
    string content;
    file.seekg(0, ios::end);
    content.reserve(file.tellg());
    file.seekg(0, ios::beg);
    content.assign(
        istreambuf_iterator<char>(file),
        istreambuf_iterator<char>());
    return content;
}

int main(int argc, char *argv[])
{
    string xmlObject = loadEntireFile("../xml/Object.xml");
    string xmlSignedInfo = loadEntireFile("../xml/SignedInfo.xml");
    vector<unsigned char> xmlDigestValue = base64toBinary(loadEntireFile("../xml/DigestValue.txt"));
    vector<unsigned char> xmlSignatureValue = base64toBinary(loadEntireFile("../xml/SignatureValue.txt"));
    string xmlX509Certificate = loadEntireFile("../xml/X509Certificate.pem");


    HCRYPTPROV hProv = 0;
    if(CryptAcquireContext(&hProv, 0, NULL, PROV_GOST_2001_DH, CRYPT_VERIFYCONTEXT))
        if(checkHash(xmlObject, xmlDigestValue, hProv))
        {
            Certificate x509(xmlX509Certificate);

            if(x509.isValid())
                if(checkSignature(xmlSignedInfo, xmlSignatureValue, x509, hProv))
                    cout << "Signature verified!" << endl;
                else
                    error("Invalid signature");
            else
                error("Cerfiticate not trusted");
        }
        else
            error("Hashes is not equal");
    else
        error("Can't acquire context");

    if(hProv)
        CryptReleaseContext(hProv, 0);
}

// session hash calculation
/*HCRYPTKEY hSessKey = NULL;
if(!CryptDeriveKey(hProv, CALG_G28147, hHash, CRYPT_EXPORTABLE, &hSessKey))
    return error("CryptDeriveKey() failed");
if(!CryptHashSessionKey(hHash, hSessKey, 0))
    return error("CryptHashSessionKey() failed");*/
