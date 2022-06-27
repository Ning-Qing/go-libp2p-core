package crypto

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"github.com/Hyperledger-TWGC/ccs-gm/sm2"
	"github.com/Hyperledger-TWGC/ccs-gm/x509"
	pb "github.com/libp2p/go-libp2p-core/crypto/pb"
	"github.com/libp2p/go-libp2p-core/internal/catch"
)

var (
	ErrNotSM2PubKey  = errors.New("not an sm2 public key")
	ErrNotSM2PrivKey = errors.New("not an sm2 private key")
)

type SM2PrivateKey struct {
	priv *sm2.PrivateKey
}

type SM2PublicKey struct {
	pub *sm2.PublicKey
}

type SM2Sig struct {
	R, S *big.Int
}

// GenerateSM2KeyPair generates a new sm2 private and public key
func GenerateSM2KeyPair(src io.Reader) (PrivKey, PubKey, error) {
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &SM2PrivateKey{priv: priv}, &SM2PublicKey{pub: &priv.PublicKey}, nil
}

func (smPriv *SM2PrivateKey) Equals(o Key) bool {
	return basicEquals(smPriv, o)
}

func (smPriv *SM2PrivateKey) Raw() (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "sm2 private-key marshal") }()
	return x509.MarshalECPrivateKey(smPriv.priv)
}

func (smPriv *SM2PrivateKey) Type() pb.KeyType {
	return pb.KeyType_SM2
}

func (smPriv *SM2PrivateKey) Sign(data []byte) (res []byte, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "sm2 signing") }()
	r, s, err := sm2.Sign(rand.Reader, smPriv.priv, data)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(SM2Sig{
		R: r,
		S: s,
	})
}

func (smPriv *SM2PrivateKey) GetPublic() PubKey {
	return &SM2PublicKey{pub: &smPriv.priv.PublicKey}
}

func (smPub *SM2PublicKey) Equals(o Key) bool {
	return basicEquals(smPub, o)
}

func (smPub *SM2PublicKey) Raw() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(smPub.pub)
}

func (smPub *SM2PublicKey) Type() pb.KeyType {
	return pb.KeyType_SM2
}

func (smPub *SM2PublicKey) Verify(data []byte, sigBytes []byte) (success bool, err error) {
	defer func() {
		catch.HandlePanic(recover(), &err, "sm2 signature verification")

		// Just to be extra paranoid.
		if err != nil {
			success = false
		}
	}()

	sig := new(SM2Sig)
	if _, err := asn1.Unmarshal(sigBytes, sig); err != nil {
		return false, err
	}

	return sm2.Verify(smPub.pub, data, sig.R, sig.S), nil
}

// UnmarshalECDSAPrivateKey returns a private key from x509 bytes
func UnmarshalSM2PrivateKey(data []byte) (res PrivKey, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "ECDSA private-key unmarshal") }()

	privIfc, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return nil, err
	}

	priv, ok := privIfc.(*sm2.PrivateKey)
	if !ok {
		return nil, ErrNotSM2PrivKey
	}

	return &SM2PrivateKey{priv: priv}, nil
}

func UnmarshalSM2PublicKey(data []byte) (key PubKey, err error) {
	defer func() { catch.HandlePanic(recover(), &err, "SM2 public-key unmarshal") }()

	pubIfc, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}

	pub, ok := pubIfc.(*sm2.PublicKey)
	if !ok {
		return nil, ErrNotSM2PubKey
	}

	return &SM2PublicKey{pub: pub}, nil
}

func SM2KeyPairFromKey(priv *sm2.PrivateKey) (PrivKey, PubKey, error) {
	if priv == nil {
		return nil, nil, ErrNilPrivateKey
	}

	return &SM2PrivateKey{priv}, &SM2PublicKey{&priv.PublicKey}, nil
}

func SM2PublicKeyFromPubKey(pub sm2.PublicKey) (PubKey, error) {
	return &SM2PublicKey{pub: &pub}, nil
}
