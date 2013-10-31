#pragma once
#include "Crypto\aescpp.h"

void aes256cbc(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out);
void aes128ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out);

int hex2bin(const char* hex, int n, void* pbin); //Primarily used for interpreting Keys and IVs

void decompress(u8 *in, u64 in_len, u8 *out, u64 out_len); //For zip decompression of arbitrary data

static inline u8 be8(u8 *p)
{
	return *p;
}

static inline u16 be16(u8 *p)
{
	u16 a;

	a  = p[0] << 8;
	a |= p[1];

	return a;
}

static inline u32 be32(u8 *p)
{
	u32 a;

	a  = p[0] << 24;
	a |= p[1] << 16;
	a |= p[2] <<  8;
	a |= p[3] <<  0;

	return a;
}

static inline u64 be64(u8 *p)
{
	u32 a, b;

	a = be32(p);
	b = be32(p + 4);

	return ((u64)a<<32) | b;
}

static inline void wbe32(u8 *p, u32 v)
{
	p[0] = v >> 24;
	p[1] = v >> 16;
	p[2] = v >>  8;
	p[3] = v;
}

static inline void wbe64(u8 *p, u64 v)
{
	wbe32(p + 4, v);
	v >>= 32;
	wbe32(p, v);
}