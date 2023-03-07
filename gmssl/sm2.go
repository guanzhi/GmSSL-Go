/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
/* +build cgo */
package gmssl

/*
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>

SM2_KEY *sm2_key_new(void) {
	SM2_KEY *sm2_key;
	if (!(sm2_key = (SM2_KEY *)malloc(sizeof(SM2_KEY)))) {
		error_print();
		return NULL;
	}
	return sm2_key;
}

void sm2_key_free(SM2_KEY *sm2_key) {
	if (sm2_key) {
		gmssl_secure_clear(sm2_key, sizeof(SM2_KEY));
		free(sm2_key);
	}
}

SM2_SIGN_CTX *sm2_sign_ctx_new(void) {
	SM2_SIGN_CTX *sm2_sign_ctx;
	if (!(sm2_sign_ctx = (SM2_SIGN_CTX *)malloc(sizeof(SM2_SIGN_CTX)))) {
		error_print();
		return NULL;
	}
	return sm2_sign_ctx;
}

void sm2_sign_ctx_free(SM2_SIGN_CTX *sm2_sign_ctx) {
	if (sm2_sign_ctx) {
		gmssl_secure_clear(sm2_sign_ctx, sizeof(SM2_SIGN_CTX));
		free(sm2_sign_ctx);
	}
}













int sm2_private_key_info_encrypt_to_pem_file(const SM2_KEY *sm2_key, const char *pass, const char *file)
{
	return 1;
}

int sm2_private_key_info_decrypt_from_pem_file(SM2_KEY *sm2_key, const char *pass, const char *file)
{
	return 1;
}

int sm2_public_key_info_to_pem_file(const SM2_KEY *sm2_key, const char *file)
{
	return 1;
}

int sm2_public_key_info_from_pem_file(SM2_KEY *sm2_key, const char *file)
{
	return 1;
}


void sm2_key_to_public_key(const SM2_KEY *sm2_key, SM2_KEY *sm2_pub)
{
	memset(sm2_pub, 0, sizeof(SM2_KEY));
	sm2_pub->public_key = sm2_key->public_key;
}

*/
import "C"

import (
	"unsafe"
	"errors"
	"runtime"
)


type SM2PrivateKey struct {
	sm2_key *C.SM2_KEY
}

type SM2PublicKey struct {
	sm2_pub *C.SM2_KEY
}

func GenerateSM2PrivateKey() (*SM2PrivateKey, error) {
	sm2_key := C.sm2_key_new()
	if sm2_key == nil {
		return nil, errors.New("Malloc failure")
	}
	ret := &SM2PrivateKey{sm2_key}
	runtime.SetFinalizer(ret, func(ret *SM2PrivateKey) {
		C.sm2_key_free(ret.sm2_key)
	})
	if C.sm2_key_generate(sm2_key) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return ret, nil
}

func SM2PrivateKeyInfoDecryptFromPEM(pass string, file string) (*SM2PrivateKey, error) {
	sm2_key := C.sm2_key_new()
	if sm2_key == nil {
		return nil, errors.New("Malloc failure")
	}
	ret := &SM2PrivateKey{sm2_key}
	runtime.SetFinalizer(ret, func(ret *SM2PrivateKey) {
		C.sm2_key_free(ret.sm2_key)
	})

	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	file_str := C.CString(file)
	defer C.free(unsafe.Pointer(file_str))

	if C.sm2_private_key_info_decrypt_from_pem_file(sm2_key, pass_str, file_str) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return ret, nil
}

func (sk *SM2PrivateKey) toEncryptedPrivateKeyInfoPEM(pass string, file string) error {
	pass_str := C.CString(pass)
	defer C.free(unsafe.Pointer(pass_str))

	file_str := C.CString(file)
	defer C.free(unsafe.Pointer(file_str))

	if C.sm2_private_key_info_encrypt_to_pem_file(sk.sm2_key, pass_str, file_str) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (sk *SM2PrivateKey) toPublicKey() (*SM2PublicKey, error) {
	sm2_pub := C.sm2_key_new()
	if sm2_pub == nil {
		return nil, errors.New("Malloc failure")
	}
	ret := &SM2PublicKey{sm2_pub}
	runtime.SetFinalizer(ret, func(ret *SM2PublicKey) {
		C.sm2_key_free(ret.sm2_pub)
	})

	C.sm2_key_to_public_key(sk.sm2_key, sm2_pub)
	return ret, nil
}

func (sk *SM2PrivateKey) toPublicKeyInfoPEM(file string) error {
	file_str := C.CString(file)
	defer C.free(unsafe.Pointer(file_str))

	if C.sm2_public_key_info_to_pem_file(sk.sm2_key, file_str) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (sk *SM2PrivateKey) SignDigest(dgst []byte) ([]byte, error) {
	sig := make([]byte, C.SM2_MAX_SIGNATURE_SIZE)
	var siglen C.size_t

	if C.sm2_sign(sk.sm2_key, (*C.uchar)(&dgst[0]), (*C.uchar)(&sig[0]), &siglen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return sig[:siglen], nil
}

func (sk *SM2PrivateKey) Decrypt(in []byte) ([]byte, error) {
	outbuf := make([]byte, C.SM2_MAX_PLAINTEXT_SIZE)
	var outlen C.size_t
	if C.sm2_decrypt(sk.sm2_key, (*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}

func SM2PublicKeyInfoFromPEM(file string) (*SM2PublicKey, error) {
	sm2_pub := C.sm2_key_new()
	if sm2_pub == nil {
		return nil, errors.New("Libgmssl inner error")
	}
	ret := &SM2PublicKey{sm2_pub}
	runtime.SetFinalizer(ret, func(ret *SM2PublicKey) {
		C.sm2_key_free(ret.sm2_pub)
	})

	file_str := C.CString(file)
	defer C.free(unsafe.Pointer(file_str))

	if C.sm2_public_key_info_from_pem_file(sm2_pub, file_str) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return ret, nil
}

func (pk *SM2PublicKey) toPublicKeyInfoPEM(file string) error {
	file_str := C.CString(file)
	defer C.free(unsafe.Pointer(file_str))

	if C.sm2_public_key_info_to_pem_file(pk.sm2_pub, file_str) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (pk *SM2PublicKey) VerifyDigest(dgst []byte, sig []byte) error {
	if len(dgst) != C.SM3_DIGEST_SIZE {
		return errors.New("Malloc failure")
	}
	if 1 != C.sm2_verify(pk.sm2_pub, (*C.uchar)(&dgst[0]), (*C.uchar)(&sig[0]), C.size_t(len(sig))) {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (pk *SM2PublicKey) Encrypt(in []byte) ([]byte, error) {
	outbuf := make([]byte, C.SM2_MAX_CIPHERTEXT_SIZE)
	var outlen C.size_t
	if C.sm2_encrypt(pk.sm2_pub, (*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}

func (pk *SM2PublicKey) ComputeZ(id string) ([]byte, error) {
	outbuf := make([]byte, C.SM3_DIGEST_SIZE)

	id_str := C.CString(id)
	defer C.free(unsafe.Pointer(id_str))

	if C.sm2_compute_z((*C.uchar)(&outbuf[0]), &(pk.sm2_pub.public_key), id_str, C.strlen(id_str)) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf, nil
}

type SM2SignContext struct {
	sm2_sign_ctx *C.SM2_SIGN_CTX
}

func NewSM2SignContext(sk *SM2PrivateKey, id string) (*SM2SignContext, error) {
	sm2_sign_ctx := C.sm2_sign_ctx_new()
	if sm2_sign_ctx == nil {
		return nil, errors.New("Malloc failure")
	}
	ret := &SM2SignContext{sm2_sign_ctx}
	runtime.SetFinalizer(ret, func(ret *SM2SignContext) {
		C.sm2_sign_ctx_free(ret.sm2_sign_ctx)
	})
	id_str := C.CString(id)
	defer C.free(unsafe.Pointer(id_str))
	if C.sm2_sign_init(sm2_sign_ctx, sk.sm2_key, id_str, C.strlen(id_str)) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return ret, nil
}

func (ctx *SM2SignContext) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if C.sm2_sign_update(ctx.sm2_sign_ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (ctx *SM2SignContext) Finish() ([]byte, error) {
	outbuf := make([]byte, C.SM2_MAX_SIGNATURE_SIZE)
	var outlen C.size_t
	if C.sm2_sign_finish(ctx.sm2_sign_ctx, (*C.uchar)(unsafe.Pointer(&outbuf[0])), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}

type SM2VerifyContext struct {
	sm2_sign_ctx *C.SM2_SIGN_CTX
}

func NewSM2VerifyContext(pk *SM2PublicKey, id string) (*SM2VerifyContext, error) {
	sm2_sign_ctx := C.sm2_sign_ctx_new()
	if sm2_sign_ctx == nil {
		return nil, errors.New("Malloc failure")
	}
	ret := &SM2VerifyContext{sm2_sign_ctx}
	runtime.SetFinalizer(ret, func(ret *SM2VerifyContext) {
		C.sm2_sign_ctx_free(ret.sm2_sign_ctx)
	})
	id_str := C.CString(id)
	defer C.free(unsafe.Pointer(id_str))
	if C.sm2_verify_init(sm2_sign_ctx, pk.sm2_pub, id_str, C.strlen(id_str)) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return ret, nil
}

func (ctx *SM2VerifyContext) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if C.sm2_verify_update(ctx.sm2_sign_ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}

func (ctx *SM2VerifyContext) Finish(sig []byte) error {
	if C.sm2_verify_finish(ctx.sm2_sign_ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig))) != 1 {
		return errors.New("Libgmssl inner error")
	}
	return nil
}
