package crypto

import (
	"Open_IM/pkg/utils/crypto/ecies"
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEncrypt(t *testing.T) {
	const PRIVATE = "3621626f8ed1fd98bbd27b9a6af0f8fe3377a6dd66bfa269004da8abfb972fcd"
	const PRIVATE2 = "a1cece26300160d3ce697b72f62f73f3519cef5b418bca0ae1f34616f455c450"
	var pubKeyBuff = Public(PRIVATE)
	fmt.Println("publicKey: \t", fmt.Sprintf("%x", pubKeyBuff))

	// https://github.com/wsddn/go-ecdh/blob/48726bab92085232373de4ec5c51ce7b441c63a0/elliptic.go#L10
	// crypto.PrivateKey

	// elliptic.Curve.ScalarMult()

	// prv2 = ecies.ImportECDSA(PRIVATE)
	// b := []byte(PRIVATE)
	// var prvKey, err = HexToECDSA(PRIVATE)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Println("prvKey: \t", prvKey)

	var prvKey = hexToPrivateKey(PRIVATE)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	fmt.Println("prvKey: \t", prvKey)

	var prvKey2 = hexToPrivateKey(PRIVATE2)
	fmt.Println("prvKey2: \t", prvKey2)

	// var pubKey2, err2 = HexToECDSA(pubKey)
	// if err2 != nil {
	// 	fmt.Println(err2)
	// }
	// fmt.Println("pubKey2: \t", pubKey2)

	pubKey4 := fromPublicKey("0x04bc3c5053c9d3143861eb1e8322d268c1da5c3aa2b5a42343dfcdba9a0317a1ee866a0d2834c69325d2a72ff8aad310395c178903b3b4719cab86736851889dcf")

	fmt.Println("pubKey4: \t", pubKey4)

	pubKey := prvKey.PublicKey
	pubKey2 := prvKey2.PublicKey

	shareKey, err3 := GenerateSharedSecret(*prvKey, pubKey2)
	if err3 != nil {
		fmt.Println(err3)
	}

	fmt.Println("shareKey: \t", shareKey)
	fmt.Println("shareKey hex: \t", fmt.Sprintf("%x", shareKey))

	shareKey2, err4 := GenerateSharedSecret(*prvKey2, pubKey)
	if err4 != nil {
		fmt.Println(err4)
	}
	fmt.Println("shareKey2: \t", shareKey2)
	fmt.Println("shareKey2 hex: \t", fmt.Sprintf("%x", shareKey2))

	hash := sha512.Sum512([]byte(shareKey))

	fmt.Println("hash: \t", fmt.Sprintf("%x", hash))

	iv, err5 := GenRandomBytes(16)
	if err5 != nil {
		fmt.Println(err5)
	}
	fmt.Println("iv: \t", fmt.Sprintf("%x", iv))
	// iv = []byte("97790e46cf346320ad5c6bf0234f3b65")
	iv = []byte{186, 43, 16, 120, 107, 183, 38, 126, 245, 37, 21, 113, 16, 103, 185, 95}

	const plaintext = "hello"
	encryptionKey := hash[0:32]
	fmt.Println("encryptionKey: \t", fmt.Sprintf("%x", encryptionKey))
	macKey := hash[32:]
	fmt.Println("macKey: \t", fmt.Sprintf("%x", macKey))

	ciphertext, err6 := ecies.Ase256(plaintext, string(encryptionKey), string(iv), aes.BlockSize)
	if err6 != nil {
		fmt.Println(err5)
	}
	fmt.Println("ciphertext: \t", ciphertext)

	var buffer bytes.Buffer //Buffer是一个实现了读写方法的可变大小的字节缓冲

	buffer.Write(iv)
	buffer.Write(pubKeyBuff)
	ct, err := hex.DecodeString(ciphertext)
	if err != nil {
		fmt.Println(err)
		return
	}
	buffer.Write(ct)

	dataToMac := buffer.Bytes() //得到了b1+b2的结果

	fmt.Println("dataToMac: \t", fmt.Sprintf("%x", dataToMac))

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, macKey)

	// Write Data to it
	h.Write(dataToMac)

	// Get result and encode as hexadecimal string
	mac := hex.EncodeToString(h.Sum(nil))

	fmt.Println("mac: " + mac)

	var serializedCiphertextBuffer bytes.Buffer //Buffer是一个实现了读写方法的可变大小的字节缓冲

	serializedCiphertextBuffer.Write(iv)
	serializedCiphertextBuffer.Write(pubKeyBuff)
	macBuff, err7 := hex.DecodeString(mac)
	if err7 != nil {
		fmt.Println(err7)
		return
	}
	serializedCiphertextBuffer.Write(macBuff)
	serializedCiphertextBuffer.Write(ct)

	serializedCiphertext := serializedCiphertextBuffer.Bytes() //得到了b1+b2的结果

	fmt.Println("serializedCiphertextBuffer： \t", hex.EncodeToString(serializedCiphertext))

}


func TestDecrypt(t *testing.T) {

}