package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
)

func TestSM2BasicSignAndVerify(t *testing.T) {
	priv, pub, err := GenerateSM2KeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("hello! and welcome to some awesome crypto primitives")

	sig, err := priv.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("signature didnt match")
	}

	// change data
	data[0] = ^data[0]
	ok, err = pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}

	if ok {
		t.Fatal("signature matched and shouldn't")
	}
}

func TestSM2SignZero(t *testing.T) {
	priv, pub, err := GenerateSM2KeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 0)
	sig, err := priv.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := pub.Verify(data, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("signature didn't match")
	}
}

func TestSM2MarshalLoop(t *testing.T) {
	priv, pub, err := GenerateSM2KeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privB, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	privNew, err := UnmarshalPrivateKey(privB)
	if err != nil {
		t.Fatal(err)
	}

	if !priv.Equals(privNew) || !privNew.Equals(priv) {
		t.Fatal("keys are not equal")
	}

	pubB, err := MarshalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubNew, err := UnmarshalPublicKey(pubB)
	if err != nil {
		t.Fatal(err)
	}

	if !pub.Equals(pubNew) || !pubNew.Equals(pub) {
		t.Fatal("keys are not equal")
	}

}

func TestSM2PublicKeyFromPubKey(t *testing.T) {
	sm2PrivK, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privK, _, err := SM2KeyPairFromKey(sm2PrivK)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("Hello world!")
	signature, err := privK.Sign(data)
	if err != nil {
		t.Fatal(err)
	}

	pubKey, err := SM2PublicKeyFromPubKey(sm2PrivK.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := pubKey.Verify(data, signature)
	if err != nil {
		t.Fatal(err)
	}

	if !ok {
		t.Fatal("signature didn't match")
	}

	pubB, err := MarshalPublicKey(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	pubNew, err := UnmarshalPublicKey(pubB)
	if err != nil {
		t.Fatal(err)
	}

	if !pubKey.Equals(pubNew) || !pubNew.Equals(pubKey) {
		t.Fatal("keys are not equal")
	}
}
