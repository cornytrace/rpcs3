#pragma once
#include "Loader.h"
#include "ELF64.h"
#include "Utilities\Utility.h"

struct SceHeader
{
	u32 se_magic;
	u32 se_hver;
	u16 se_flags;
	u16 se_type;
	u32 se_meta;
	u64 se_hsize;
	u64 se_esize;

	void Load(vfsStream& f)
	{
		se_magic		= Read32(f);
		se_hver			= Read32(f);
		se_flags		= Read16(f);
		se_type			= Read16(f);
		se_meta			= Read32(f);
		se_hsize		= Read64(f);
		se_esize		= Read64(f);
	}

	void Show()
	{
		ConLog.Write("Magic: %08x",			se_magic);
		ConLog.Write("Class: %s",			"SELF");
		ConLog.Write("hver: 0x%08x",		se_hver);
		ConLog.Write("flags: 0x%04x",		se_flags);
		ConLog.Write("type: 0x%04x",		se_type);
		ConLog.Write("meta: 0x%08x",		se_meta);
		ConLog.Write("hsize: 0x%llx",		se_hsize);
		ConLog.Write("esize: 0x%llx",		se_esize);
	}

	bool CheckMagic() const { return se_magic == 0x53434500; }
};

struct SelfHeader
{
	u64 se_htype;
	u64 se_appinfooff;
	u64 se_elfoff;
	u64 se_phdroff;
	u64 se_shdroff;
	u64 se_secinfoff;
	u64 se_sceveroff;
	u64 se_controloff;
	u64 se_controlsize;
	u64 pad;

	void Load(vfsStream& f)
	{
		se_htype		= Read64(f);
		se_appinfooff	= Read64(f);
		se_elfoff		= Read64(f);
		se_phdroff		= Read64(f);
		se_shdroff		= Read64(f);
		se_secinfoff	= Read64(f);
		se_sceveroff	= Read64(f);
		se_controloff	= Read64(f);
		se_controlsize	= Read64(f);
		pad				= Read64(f);
	}

	void Show()
	{
		ConLog.Write("header type: 0x%llx",					se_htype);
		ConLog.Write("app info offset: 0x%llx",				se_appinfooff);
		ConLog.Write("elf offset: 0x%llx",					se_elfoff);
		ConLog.Write("program header offset: 0x%llx",		se_phdroff);
		ConLog.Write("section header offset: 0x%llx",		se_shdroff);
		ConLog.Write("section info offset: 0x%llx",			se_secinfoff);
		ConLog.Write("sce version offset: 0x%llx",			se_sceveroff);
		ConLog.Write("control info offset: 0x%llx",			se_controloff);
		ConLog.Write("control info size: 0x%llx",			se_controlsize);
	}
};

struct Key {
	u8 key[32];
	u8 iv[16];

	int pub_avail;
	int priv_avail;
	u8 pub[40];
	u8 priv[21];
	u32 ctype;
};

struct SelfSections{
	u32 offset;
	u32 size;
	u32 compressed;
	u32 size_uncompressed;
	u32 elf_offset;
};

struct SelfSection {
	u32 idx;
	u64 offset;
	u64 size;
	u32 compressed;
	u32 encrypted;
	u64 next;
};

struct Keylist {
	u32 n;
	Key *keys;
};

static int qsort_compare(const void *a, const void *b)
{
	const struct SelfSection *sa, *sb;
	sa = (SelfSection*)a;
	sb = (SelfSection*)b;

	if (sa->offset > sb->offset)
		return 1;
	else if(sa->offset < sb->offset)
		return -1;
	else
		return 0;
}

class SELFLoader : public LoaderBase
{
	vfsStream& self_f;

	SceHeader sce_hdr;
	SelfHeader self_hdr;

	Elf64_Ehdr ehdr;
	Array<Elf64_Phdr> phdr_arr;
	Array<Elf64_Shdr> shdr_arr;

	SelfSections self_sections[255];
	int n_sections;
	Keylist *klist;

	u32 meta_offset;
	u64 header_len;
	u32 meta_len;
	u32 meta_n_hdr;

public:
	SELFLoader(vfsStream& f);

	virtual bool LoadInfo();
	virtual bool LoadData(u64 offset = 0);
	bool DecryptSELF(vfsStream& self, vfsStream& elf);
	Keylist* LoadKeys(void);
	int DecryptHeader(u8 *buf, struct Keylist *klist);
	int DecryptData(u8 *buf);

	void ReadSection(u8 *buf, u32 i, struct SelfSection *sec);
	void ReadSections(u8 *buf);

	int WriteElf(u8 *buf, vfsStream& elf);
};