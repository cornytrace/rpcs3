#include "stdafx.h"
#include "SELF.h"
#include "ELF64.h"
#include <wx/msw/iniconf.h>

SELFLoader::SELFLoader(vfsStream& f)
	: self_f(f)
	, LoaderBase()
{ 
}

bool SELFLoader::LoadInfo()
{
	if(!self_f.IsOpened()) return false;
	self_f.Seek(0);
	sce_hdr.Load(self_f);
	self_hdr.Load(self_f);
	
	self_f.Seek(self_hdr.se_elfoff);
	ehdr.Load(self_f);

	self_f.Seek(self_hdr.se_phdroff);
	for(u32 i=0; i<ehdr.e_phnum; ++i)
	{
		Elf64_Phdr* phdr = new Elf64_Phdr();
		phdr->Load(self_f);
		phdr_arr.Move(phdr);
	}

	self_f.Seek(self_hdr.se_shdroff);
	for(u32 i=0; i<ehdr.e_shnum; ++i)
	{
		Elf64_Shdr* shdr = new Elf64_Shdr();
		shdr->Load(self_f);
		shdr_arr.Move(shdr);
	}

	if(!sce_hdr.CheckMagic()) return false;

	return true;
}

bool SELFLoader::LoadData(u64 offset)
{
	if(!self_f.IsOpened()) return false;

	//Todo: implement virtual files stored only in memory?
	vfsLocalFile& elf_f = *new vfsLocalFile(wxGetCwd() + "\\temp.elf",vfsReadWrite);

	sce_hdr.Show();
	self_hdr.Show();

	if(!DecryptSELF(self_f,elf_f))
	{
		ConLog.Error("SELF decryption failed");
	}

	ELF64Loader l(elf_f);
	if( !l.LoadEhdrInfo(0) ||
		!l.LoadPhdrInfo(ehdr.e_phoff) ||
		!l.LoadShdrInfo(ehdr.e_shoff) ||
		!l.LoadData(0) )
	{
		ConLog.Error("Broken SELF file.");
		return false;
	}

	machine = l.GetMachine();
	entry = l.GetEntry();

	return true;
}

bool SELFLoader::DecryptSELF(vfsStream& self, vfsStream& elf)
{
	u8 *buf = new u8[self.GetSize()];
	self.Seek(0);
	self.Read(buf,self.GetSize());

	klist = LoadKeys();
	if (klist == NULL)
		return false;

	if (DecryptHeader(buf, klist) < 0)
		return false;

	ReadSections(buf);

	if (DecryptData(buf) < 0)
		return false;

	if (WriteElf(buf, elf) < 0)
		return false;

	return true;
}

Keylist* SELFLoader::LoadKeys(void)
{
	wxIniConfig* m_Keyfile = new wxIniConfig( wxEmptyString, wxEmptyString,
			wxGetCwd() + "\\app-key.txt",
			wxEmptyString, wxCONFIG_USE_LOCAL_FILE );

	klist = new Keylist;
	wxString *key;
	wxString *iv;
	wxString *priv;
	wxString *pub;

	u8 binkey[32];
	u8 biniv[16];
	u8 binpriv[21];
	u8 binpub[40];

	klist->n = m_Keyfile->GetNumberOfGroups();
	klist->keys = new Key[klist->n];
	for(int i=0; i < klist->n; i++) {
		//hex2bin("79481839C406A632BDB4AC093D73D99AE1587F24CE7E69192C1CD0010274A8AB",64,binkey);
		//hex2bin("6F0F25E1C8C4B7AE70DF968B04521DDA",32,biniv);
		//hex2bin("",42,binpriv);
		//hex2bin("8CA6905F46148D7D8D84D2AFCEAE61B41E6750FC22EA435DFA61FCE6F4F860EE4F54D9196CA5290E",80,binpub);
		m_Keyfile->Read("erk",key);
		m_Keyfile->Read("riv",iv);
		m_Keyfile->Read("pub",pub);
		m_Keyfile->Read("priv",priv);
		hex2bin(key->ToAscii(),64,binkey);
		hex2bin(iv->ToAscii(),32,biniv);
		hex2bin(pub->ToAscii(),80,binpub);
		hex2bin(priv->ToAscii(),42,binpriv);
		memcpy(klist->keys[0].key, binkey, sizeof(u8[32]));
		memcpy(klist->keys[0].iv, biniv, sizeof(u8[16]));
		memcpy(klist->keys[0].priv, " ", sizeof(u8[21]));
		memcpy(klist->keys[0].pub, binpub, sizeof(u8[40]));
		klist->keys[0].priv_avail = 0;
		klist->keys[0].pub_avail = 0;
	}

	//TODO: load keys from file

	return klist;
}

int SELFLoader::DecryptHeader(u8 *buf, struct Keylist *klist)
{
	u32 i, j;
	u8 tmp[0x40];
	int success = 0;

	meta_offset = sce_hdr.se_meta;
	header_len  = sce_hdr.se_hsize;
	meta_len = header_len - meta_offset;

	for (i = 0; i < klist->n; i++) {
		aes256cbc(klist->keys[i].key,
			klist->keys[i].iv,
			buf + meta_offset + 0x20,
			0x40,
			tmp);

		success = 1;
		for (j = 0x30; j < (0x10 + 0x10); j++)
			if (tmp[j] != 0)
				success = 0;
	
		for (j = 0x50; j < (0x30 + 0x10); j++)
			if (tmp[j] != 0)
			       success = 0;

		if (success == 1) {
			memcpy(buf + meta_offset + 0x20, tmp, 0x40); //First 0x10 contains the metadata key, the other 0x10 contains the IV
		}
	}

	if (success != 1)
		return -1;

	memcpy(tmp, buf + meta_offset + 0x40, 0x10);
	aes128ctr(buf + meta_offset + 0x20,
		  tmp,
		  buf + meta_offset + 0x60,
		  0x20,
		  buf + meta_offset + 0x60);

	meta_len = header_len - meta_offset;

	aes128ctr(buf + meta_offset + 0x20,
		  tmp,
		  buf + meta_offset + 0x80,
		  meta_len - 0x80,
		  buf + meta_offset + 0x80);

	return i;
}

int SELFLoader::DecryptData(u8 *buf)
{
	u32 meta_n_hdr;
	u32 i;

	u64 offset;
	u64 size;
	u32 keyid;
	u32 ivid;
	u8 *tmp;

	u8 iv[16];

	meta_n_hdr = be32(buf + meta_offset + 0x60 + 0xc);

	for (i = 0; i < meta_n_hdr; i++) {
		tmp = buf + meta_offset + 0x80 + 0x30*i;
		offset = be64(tmp);
		size = be64(tmp + 8);
		keyid = be32(tmp + 0x24);
		ivid = be32(tmp + 0x28);

		if (keyid == 0xffffffff || ivid == 0xffffffff)
			continue;

		memcpy(iv, buf + meta_offset + 0x80 + 0x30 * meta_n_hdr + ivid * 0x10, 0x10);
		aes128ctr(buf + meta_offset + 0x80 + 0x30 * meta_n_hdr + keyid * 0x10,
		          iv,
 		          buf + offset,
			  size,
			  buf + offset);
	}

	return 0;
}

void SELFLoader::ReadSection(u8 *buf, u32 i, struct SelfSection *sec)
{
	u8 *ptr;

	ptr = buf + self_hdr.se_secinfoff + i*0x20;

	sec->idx = i;
	sec->offset     = be64(ptr + 0x00);
	sec->size       = be64(ptr + 0x08);
	sec->compressed = be32(ptr + 0x10) == 2 ? 1 : 0;
	sec->encrypted  = be32(ptr + 0x20);
	sec->next       = be64(ptr + 0x20);
}

void SELFLoader::ReadSections(u8 *buf)
{
	struct SelfSection s[255];
	Elf64_Phdr p;
	u32 i;
	u32 j;
	u32 n_secs;
	u32 self_offset, elf_offset;

	memset(s, 0, sizeof s);
	for (i = 0, j = 0; i < ehdr.e_phnum; i++) {
		ReadSection(buf, i, &s[j]);
		if (s[j].compressed)
			j++;
	}

	n_secs = j;
	qsort(s, n_secs, sizeof(*s), qsort_compare);

	elf_offset = 0;
	self_offset = header_len;
	j = 0;
	i = 0;
	while (elf_offset < sce_hdr.se_esize) {
		if (i == n_secs) {
			self_sections[j].offset = self_offset;
			self_sections[j].size = sce_hdr.se_esize - elf_offset;
			self_sections[j].compressed = 0;
			self_sections[j].size_uncompressed = sce_hdr.se_esize - elf_offset;
			self_sections[j].elf_offset = elf_offset;
			elf_offset = sce_hdr.se_esize;
		} else if (self_offset == s[i].offset) {
			self_sections[j].offset = self_offset;
			self_sections[j].size = s[i].size;
			self_sections[j].compressed = 1;
			p = phdr_arr.Get(i);
			self_sections[j].size_uncompressed = p.p_filesz;
			self_sections[j].elf_offset = p.p_offset;

			elf_offset = p.p_offset + p.p_filesz;
			self_offset = s[i].next;
			i++;
		} else {
			p = phdr_arr.Get(i);
			self_sections[j].offset = self_offset;
			self_sections[j].size = p.p_offset - elf_offset;
			self_sections[j].compressed = 0;
			self_sections[j].size_uncompressed = self_sections[j].size;
			self_sections[j].elf_offset = elf_offset;

			elf_offset += self_sections[j].size;
			self_offset += s[i].offset - self_offset;
		}
		j++;
	}

	n_sections = j;
}

int SELFLoader::WriteElf(u8 *buf, vfsStream& elf)
{
	u8 *bfr;
	u32 size;
	u32 offset = 0;
	u16 n_shdr;
	u64 shstrtab_offset;
	const char shstrtab[] = ".unknown\0\0";
	Elf64_Shdr s;

	for (int i = 0; i < n_sections; i++) {
		offset = self_sections[i].elf_offset;
		elf.Seek(offset);

		if (self_sections[i].compressed) {
			size = self_sections[i].size_uncompressed;

			bfr = new u8[size];

			offset += size;
	
			decompress(buf + self_sections[i].offset,
			           self_sections[i].size,
				   bfr, size);

			elf.Write(bfr,size);
			delete bfr;
		} else {
			bfr = buf + self_sections[i].offset;
			size = self_sections[i].size;
			offset += size;
	
			elf.Write(bfr,size);
		}
	}

	n_shdr = shdr_arr.GetCount();
	shstrtab_offset = ehdr.e_shoff + n_shdr * 0x40;

	for (int i = 0; i < n_shdr; i++) {
		s = shdr_arr.Get(i);

		s.sh_name = 0; //Todo: if possible, retrieve original name from file?
		if (s.sh_type == 3) {
			s.sh_offset = shstrtab_offset;
			s.sh_size = sizeof shstrtab;
		}

		u8 *shdr = buf + self_hdr.se_shdroff + (i * 0x40);
		wbe32(shdr + 0*4, s.sh_name);
		wbe32(shdr + 1*4, s.sh_type);
		wbe64(shdr + 2*4, s.sh_flags);
		wbe64(shdr + 2*4 + 1*8, s.sh_addr);
		wbe64(shdr + 2*4 + 2*8, s.sh_offset);
		wbe64(shdr + 2*4 + 3*8, s.sh_size);
		wbe32(shdr + 2*4 + 4*8, s.sh_link);
		wbe32(shdr + 3*4 + 4*8, s.sh_info);
		wbe64(shdr + 4*4 + 4*8, s.sh_addralign);
		wbe64(shdr + 4*4 + 5*8, s.sh_entsize);
	}

	elf.Seek(ehdr.e_shoff);	
	elf.Write(buf + self_hdr.se_shdroff,0x40*n_shdr);

	elf.Seek(shstrtab_offset);
	elf.Write(shstrtab, sizeof shstrtab);

	return 0;
}