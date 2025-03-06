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
