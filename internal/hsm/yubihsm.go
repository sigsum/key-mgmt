package hsm

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
	"io"

	"github.com/certusone/yubihsm-go"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
)

type YubiHSMSigner struct {
	session   *yubihsm.SessionManager
	keyId     uint16
	publicKey ed25519.PublicKey
}

func NewYubiHSMSigner(conn string /* host:port */, authId uint16, authPassword string, keyId uint16) (*YubiHSMSigner, error) {
	sess, err := yubihsm.NewSessionManager(connector.NewHTTPConnector(conn), authId, authPassword)
	if err != nil {
		return nil, err
	}
	pub, err := getEd25519PublicKey(sess, keyId)
	if err != nil {
		return nil, err
	}

	return &YubiHSMSigner{session: sess, keyId: keyId, publicKey: pub}, nil
}

func (hsm *YubiHSMSigner) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	signature, err := sign(hsm.session, hsm.keyId, msg)
	if err != nil {
		return nil, err
	}
	// Check that signature is valid: an invalid signature could
	// be sign of a fault attack on the HSM, and leak information
	// about the private key.
	if !ed25519.Verify(hsm.publicKey, msg, signature) {
		return nil, fmt.Errorf("invalid signature from the hsm")
	}
	return signature, nil
}

func (hsm *YubiHSMSigner) Public() crypto.PublicKey {
	return hsm.publicKey
}

// Close closes the connection to the HSM
func (hsm *YubiHSMSigner) Close() {
	hsm.session.Destroy()
}

func getEd25519PublicKey(session *yubihsm.SessionManager, keyID uint16) (ed25519.PublicKey, error) {
	command, err := commands.CreateGetPubKeyCommand(keyID)
	if err != nil {
		return nil, err
	}
	resp, err := session.SendEncryptedCommand(command)
	if err != nil {
		return nil, err
	}
	respCmd, matched := resp.(*commands.GetPubKeyResponse)
	if !matched {
		return nil, fmt.Errorf("unexpected response type %T", resp)
	}
	if respCmd.Algorithm != commands.AlgorithmED25519 || len(respCmd.KeyData) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected key type, alg %d, size %d", respCmd.Algorithm, len(respCmd.KeyData))
	}
	return ed25519.PublicKey(respCmd.KeyData), nil
}

func sign(session *yubihsm.SessionManager, keyID uint16, data []byte) ([]byte, error) {
	command, err := commands.CreateSignDataEddsaCommand(keyID, data)
	if err != nil {
		return nil, err
	}
	resp, err := session.SendEncryptedCommand(command)
	if err != nil {
		return nil, err
	}
	respCmd, matched := resp.(*commands.SignDataEddsaResponse)
	if !matched {
		return nil, fmt.Errorf("unexpected response type %T", resp)
	}
	return respCmd.Signature, nil
}
