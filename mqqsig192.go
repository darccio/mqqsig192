package mqqsig192

/*
#cgo pkg-config: libsodium
#include "mqq-sign.h"
#include "mqq-verify.h"
#include "keygen.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

const (
	PublicKeySize = C.PUBLIC_KEY_SIZE_BYTES
	PrivateKeySize = C.PRIVATE_KEY_SIZE_BYTES
	SignatureSize = C.N / 8
)

// GenerateKey generates a public/private key pair.
func GenerateKey() (publicKey *[PublicKeySize]byte, privateKey *[PrivateKeySize]byte, err error) {
	publicKey = new([PublicKeySize]byte)
	ppublicKey := (*C.uchar)(unsafe.Pointer(publicKey))

	privateKey = new([PrivateKeySize]byte)
	pprivateKey := (*C.uchar)(unsafe.Pointer(privateKey))
	if r := C.crypto_sign_keypair(ppublicKey, pprivateKey); r != 0 {
		err = errors.New(fmt.Sprintf("crypto_sign_keypair: %d", r))
		return
	}
	return
}

func convertCArrayToByteSlice(array unsafe.Pointer, size int) (byteSlice []byte) {
	var ptr = uintptr(array)
	byteSlice = make([]byte, size)
	for i := 0; i < size; i++ {
		byteSlice[i] = byte(*(*C.uchar)(unsafe.Pointer(ptr)))
		ptr++
	}
	return
}

// Sign signs the message with privateKey and returns a signature.
func Sign(privateKey *[PrivateKeySize]byte, message []byte) (signedMessage []byte, err error) {
	var finalSize C.ulonglong
	messageSize := len(message)
	signatureSize := SignatureSize + messageSize

	psignedMessage := unsafe.Pointer(C.calloc(C.size_t(signatureSize), 1))
	upsignedMessage := (*C.uchar)(psignedMessage)
	defer C.free(psignedMessage)

	pmessage := (*C.uchar)(unsafe.Pointer(&message))
	pprivateKey := (*C.uchar)(unsafe.Pointer(privateKey))
	if r := C.crypto_sign(upsignedMessage, &finalSize, pmessage, C.ulonglong(messageSize), pprivateKey); r!= 0 {
		err = errors.New(fmt.Sprintf("crypto_sign: %d", r))
		return
	}
	signedMessage = convertCArrayToByteSlice(psignedMessage, int(finalSize))
	return
}

func convertByteSliceToCArray(byteSlice []byte) (array unsafe.Pointer) {
	size := len(byteSlice)
	array = unsafe.Pointer(C.calloc(C.size_t(size), 1))
	ptr := uintptr(array)
	for i := 0; i < size; i++ {
		*(*C.uchar)(unsafe.Pointer(ptr)) = C.uchar(byteSlice[i])
		ptr++
	}
	return
}

// Verify returns true iff sig is a valid signature of message by publicKey.
func Verify(publicKey *[PublicKeySize]byte, signedMessage []byte) (result []byte, ok bool) {
	var resultSize C.ulonglong
	result = make([]byte, len(signedMessage) - SignatureSize)
	presult := (*C.uchar)(unsafe.Pointer(&result))

	psignedMessage := convertByteSliceToCArray(signedMessage)
	upsignedMessage := (*C.uchar)(psignedMessage)
	defer C.free(psignedMessage)

	ppublicKey := (*C.uchar)(unsafe.Pointer(publicKey))
	messageSize := C.ulonglong(len(signedMessage))
	if ok = (C.crypto_sign_open(presult, &resultSize, upsignedMessage, messageSize, ppublicKey) == 0); !ok {
		return
	}
	return
}
