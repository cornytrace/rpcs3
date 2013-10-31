#include "stdafx.h";
#include "Utility.h";

void aes256cbc(u8 *key, u8 *iv_in, u8 *in, u64 len, u8 *out)
{
	AESdecrypt *aesdecrypt = new AESdecrypt;
	aesdecrypt->key256(key);
	aesdecrypt->cbc_decrypt(in,out,len,iv_in);
	delete aesdecrypt;
}

void aes128ctr(u8 *key, u8 *iv, u8 *in, u64 len, u8 *out)
{
	u32 i;
	u8 ctr[16];
	u64 tmp;

	memset(ctr, 0, 16);

	AESencrypt *aesencrypt = new AESencrypt();
	aesencrypt->key128(key);

	for (i = 0; i < len; i++) {
		if ((i & 0xf) == 0) {
			aesencrypt->encrypt(iv,ctr);
	
			// increase nonce
			tmp = be64(iv + 8) + 1;
			wbe64(iv + 8, tmp);
			if (tmp == 0)
				wbe64(iv, be64(iv) + 1);
		}
		*out++ = *in++ ^ ctr[i & 0x0f];
	}
	delete aesencrypt;
}

int hex2bin(const char* hex, int n, void* pbin)
{
	char* bin = (char*)pbin;
	int   c0, c1, i, h;
	int   j = 0;
	
	if (!pbin || !hex)
	{
		return 0;
	}

	if (n <= 0)
	{
		n = strlen(hex); /* Get hex string length */
	}

	for (i = j = 0; i < n; i += 2)
	{
		c0 = hex[i];
		if (i + 1 < n)
		{
			c1 = hex[i+1];
		}
		else
		{
			c1 = c0, c0 = '0';
		}
		if (isxdigit(c0) && isxdigit(c1))
		{
			if (isdigit(c1))
			{
				c1 -= '0';
			}
			else
			{
				c1 -= (c1 < 'G'?'A':'a') - 10;
			}
			if (isdigit(c0))
			{
				c0 -= '0';
			}
			else
			{
				c0 -= (c0 < 'G'?'A':'a') - 10;
			}
			h = (c0 << 4)|c1;
			bin[j++] = h;
		}
		else /* Ignore orphan hex digits.  */
		{
			--i; /* Try from the next char */
		}
	}
	return j;
}

void decompress(u8 *in, u64 in_len, u8 *out, u64 out_len)
{
	z_stream s;
	int ret;

	memset(&s, 0, sizeof(s));

	s.zalloc = Z_NULL;
	s.zfree = Z_NULL;
	s.opaque = Z_NULL;

	ret = inflateInit(&s);
	if (ret != Z_OK)
		ConLog.Error("inflateInit returned %d", ret);

	s.avail_in = in_len;
	s.next_in = in;

	s.avail_out = out_len;
	s.next_out = out;

	ret = inflate(&s, Z_FINISH);
	if (ret != Z_OK && ret != Z_STREAM_END)
		ConLog.Error("inflate returned %d", ret);

	inflateEnd(&s);
}