package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
)

type Handler struct {
	key   []byte
	nonce []byte

	aesblock cipher.Block
	aesgcm cipher.AEAD
}

func generateRandom(size int) ([]byte, error) {
	// генерируем криптостойкие случайные байты в b
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func NewHandler() (*Handler, error) {
	key, err := generateRandom(2 * aes.BlockSize) // ключ шифрования
	if err != nil {
		return nil, fmt.Errorf("can not generate key: %w", err)
	}

	aesblock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(aesblock)
	if err != nil {
		return nil, err
	}

	nonce, err := generateRandom(aesgcm.NonceSize())
	if err != nil {
		return nil, err
	}

	h := new(Handler)
	h.key = key
	h.nonce = nonce
	h.aesblock = aesblock
	h.aesgcm = aesgcm

	return h, nil
}

func (h *Handler) EncryptFile(filepath string) (encryptedname string, err error) {
	var file *os.File
	file, err = os.Open(filepath)
	if err != nil {
		return
	}

	var src []byte
	src, err = io.ReadAll(file)
	if err != nil {
		return
	}

	dst := h.aesgcm.Seal(nil, h.nonce, src, nil)

	encryptedname = "some.encrypted"
	var encf *os.File
	encf, err = os.OpenFile(encryptedname, os.O_CREATE, 0644)
	if err != nil {
		encryptedname = ""
		return
	}

	_, err = encf.Write(dst)

	return
}

func (h *Handler) DecryptFile(filepath string) (decryptedname string, err error) {
	var file *os.File
	file, err = os.Open(filepath)
	if err != nil {
		return
	}

	var src []byte
	src, err = io.ReadAll(file)
	if err != nil {
		return
	}

	var dst []byte
	dst, err = h.aesgcm.Open(nil, h.nonce, src, nil)
	if err != nil {
		return "", fmt.Errorf("can not aesgcm open: %w", err)
	}

	decryptedname = "some.decrypted"
	var encf *os.File
	encf, err = os.OpenFile(decryptedname, os.O_CREATE, 0644)
	if err != nil {
		return
	}

	_, err = encf.Write(dst)

	return
}

func main() {
	h, err := NewHandler()
	if err != nil {
		log.Fatalf("some error: %s", err)
	}

	encryptedfn, err := h.EncryptFile("photo.jpeg")
	if err != nil {
		log.Fatalf("some error: %s", err)
	}

	dcrtpdf, err := h.DecryptFile(encryptedfn)
	if err != nil {
		log.Fatalf("some error: %s", err)
	}

	fmt.Printf("encrypted file name: %s\n", encryptedfn)
	fmt.Printf("decrypted file name: %s\n", dcrtpdf)
}
