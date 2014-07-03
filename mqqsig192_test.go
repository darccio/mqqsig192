package mqqsig192

import (
	"testing"
)

func TestSignVerify(t *testing.T) {
	public, private, _ := GenerateKey()

	message := []byte("test message")
	signedMessage, _ := Sign(private, message)
	if _, ok := Verify(public, signedMessage); !ok {
		t.Errorf("valid signature rejected")
	}

	wrongMessage := make([]byte, len(signedMessage))
	copy(wrongMessage, signedMessage)
	wrongMessage[SignatureSize + 1] = 'r'
	if _, ok := Verify(public, wrongMessage); ok {
		t.Errorf("signature of different message accepted")
	}
}
