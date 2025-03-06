// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// secp256k1_context_create_sign_verify creates a context for signing and signature verification.
static secp256k1_context* secp256k1_context_create_sign_verify() {
	return secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
}

// secp256k1_ext_reencode_pubkey decodes then encodes a public key. It can be used to
// convert between public key formats. The input/output formats are chosen depending on the
// length of the input/output buffers.
//
// Returns: 1: conversion successful
//          0: conversion unsuccessful
// Args:    ctx:        pointer to a context object (cannot be NULL)
//  Out:    out:        output buffer that will contain the reencoded key (cannot be NULL)
//  In:     outlen:     length of out (33 for compressed keys, 65 for uncompressed keys)
//          pubkeydata: the input public key (cannot be NULL)
//          pubkeylen:  length of pubkeydata
static int secp256k1_ext_reencode_pubkey(
	const secp256k1_context* ctx,
	unsigned char *out,
	size_t outlen,
	const unsigned char *pubkeydata,
	size_t pubkeylen
) {
	secp256k1_pubkey pubkey;

	if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeydata, pubkeylen)) {
		return 0;
	}
	unsigned int flag = (outlen == 33) ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;
	return secp256k1_ec_pubkey_serialize(ctx, out, &outlen, &pubkey, flag);
}

// secp256k1_ext_scalar_mul multiplies a point by a scalar in constant time.
//
// Returns: 1: multiplication was successful
//          0: scalar was invalid (zero or overflow)
// Args:    ctx:      pointer to a context object (cannot be NULL)
//  Out:    point:    the multiplied point (usually secret)
//  In:     point:    pointer to a 64-byte public point,
//                    encoded as two 256bit big-endian numbers.
//          scalar:   a 32-byte scalar with which to multiply the point
int secp256k1_ext_scalar_mul(const secp256k1_context* ctx, unsigned char *point, const unsigned char *scalar) {
	int ret = 0;
	int overflow = 0;
	secp256k1_fe feX, feY;
	secp256k1_gej res;
	secp256k1_ge ge;
	secp256k1_scalar s;
	ARG_CHECK(point != NULL);
	ARG_CHECK(scalar != NULL);
	(void)ctx;

	// TODO(yperbasis): limit or mod?
	secp256k1_fe_set_b32_limit(&feX, point);
	secp256k1_fe_set_b32_limit(&feY, point+32);
	secp256k1_ge_set_xy(&ge, &feX, &feY);
	secp256k1_scalar_set_b32(&s, scalar, &overflow);
	if (overflow || secp256k1_scalar_is_zero(&s)) {
		ret = 0;
	} else {
		secp256k1_ecmult_const(&res, &ge, &s);
		secp256k1_ge_set_gej(&ge, &res);
		/* Note: can't use secp256k1_pubkey_save here because it is not constant time. */
		secp256k1_fe_normalize(&ge.x);
		secp256k1_fe_normalize(&ge.y);
		secp256k1_fe_get_b32(point, &ge.x);
		secp256k1_fe_get_b32(point+32, &ge.y);
		ret = 1;
	}
	secp256k1_scalar_clear(&s);
	return ret;
}