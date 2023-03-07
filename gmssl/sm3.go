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
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm3.h>
#include <gmssl/mem.h>
#include <gmssl/error.h>

SM3_CTX *sm3_ctx_new(void) {
	SM3_CTX *sm3_ctx;
	if (!(sm3_ctx = (SM3_CTX *)malloc(sizeof(SM3_CTX)))) {
		error_print();
		return NULL;
	}
	return sm3_ctx;
}

void sm3_ctx_free(SM3_CTX *sm3_ctx) {
	if (sm3_ctx) {
		gmssl_secure_clear(sm3_ctx, sizeof(SM3_CTX));
		free(sm3_ctx);
	}
}

SM3_HMAC_CTX *sm3_hmac_ctx_new(void) {
	SM3_HMAC_CTX *sm3_hmac_ctx;
	if (!(sm3_hmac_ctx = (SM3_HMAC_CTX *)malloc(sizeof(SM3_HMAC_CTX)))) {
		error_print();
		return NULL;
	}
	return sm3_hmac_ctx;
}

void sm3_hmac_ctx_free(SM3_HMAC_CTX *sm3_hmac_ctx) {
	if (sm3_hmac_ctx) {
		gmssl_secure_clear(sm3_hmac_ctx, sizeof(SM3_HMAC_CTX));
		free(sm3_hmac_ctx);
	}
}
*/
import "C"

import (
	"errors"
	"unsafe"
	"runtime"
)

type SM3Context struct {
	sm3_ctx *C.SM3_CTX
}

func NewSM3Context() (*SM3Context, error) {
	sm3_ctx := C.sm3_ctx_new()
	if sm3_ctx == nil {
		return nil, errors.New("Malloc error")
	}
	ret := &SM3Context{sm3_ctx}
	runtime.SetFinalizer(ret, func(ret *SM3Context) {
		C.sm3_ctx_free(ret.sm3_ctx)
	})
	C.sm3_init(sm3_ctx)
	return ret, nil
}

func (ctx *SM3Context) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	C.sm3_update(ctx.sm3_ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)));
	return nil
}

func (ctx *SM3Context) Finish() ([]byte, error) {
	outbuf := make([]byte, 32)
	C.sm3_finish(ctx.sm3_ctx, (*C.uchar)(unsafe.Pointer(&outbuf[0])))
	return outbuf, nil
}

func (ctx *SM3Context) Reset() error {
	C.sm3_init(ctx.sm3_ctx)
	return nil
}


type SM3HMACContext struct {
	sm3_hmac_ctx *C.SM3_HMAC_CTX
}

func NewSM3HMACContext(key []byte) (*SM3HMACContext, error) {
	sm3_hmac_ctx := C.sm3_hmac_ctx_new()
	if sm3_hmac_ctx == nil {
		return nil, errors.New("Malloc error")
	}
	ret := &SM3HMACContext{sm3_hmac_ctx}
	runtime.SetFinalizer(ret, func(ret *SM3HMACContext) {
		C.sm3_hmac_ctx_free(ret.sm3_hmac_ctx)
	})
	if len(key) < 1 || len(key) > 64 {
		return nil, errors.New("Invalid key length")
	}
	C.sm3_hmac_init(sm3_hmac_ctx, (*C.uchar)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	return ret, nil
}

func (ctx *SM3HMACContext) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	C.sm3_hmac_update(ctx.sm3_hmac_ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data)))
	return nil
}

func (ctx *SM3HMACContext) Finish() ([]byte, error) {
	outbuf := make([]byte, 32)
	C.sm3_hmac_finish(ctx.sm3_hmac_ctx, (*C.uchar)(unsafe.Pointer(&outbuf[0])))
	return outbuf, nil
}

func (ctx *SM3HMACContext) Reset(key []byte) error {
	if len(key) < 1 || len(key) > 64 {
		return errors.New("Malloc error")
	}
	C.sm3_hmac_init(ctx.sm3_hmac_ctx, (*C.uchar)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	return nil
}
