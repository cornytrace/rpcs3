#pragma once

#include "Utilities\BEType.h"
#include "Crypto\utils.h"
#include "DiscIO\DriveBlob.h"
#include "Utilities\CDUtils.h"

#include "..\3rdparty\zlib\zlib.h"

#include <string>
#include <vector>

namespace fs {
	class file;
}

struct DiscRegion {
	size_t startSector;
	size_t nextSector;
	aes_context ctx;
	bool encrypted;

	DiscRegion(size_t startSector, size_t nextSector, bool encrypted);
};

// Adapted from mkisofs iso9660.h
#define	ISODCL(from, to) (to - from + 1)

struct dual_u16 {
	u16 l;
	u16 b;
};

struct dual_u32 {
	u32 l;
	u32 b;
};

struct iso_primary_descriptor {
	char type[ISODCL(1, 1)]; /* 711 */
	char id[ISODCL(2, 6)];
	char version[ISODCL(7, 7)]; /* 711 */
	char unused1[ISODCL(8, 8)];
	char system_id[ISODCL(9, 40)]; /* achars */
	char volume_id[ISODCL(41, 72)]; /* dchars */
	char unused2[ISODCL(73, 80)];
	char volume_space_size[ISODCL(81, 88)]; /* 733 */
	char escape_sequences[ISODCL(89, 120)];
	char volume_set_size[ISODCL(121, 124)]; /* 723 */
	char volume_sequence_number[ISODCL(125, 128)]; /* 723 */
	dual_u16 logical_block_size; // [ISODCL(129, 132)]; /* 723 */
	dual_u32 path_table_size; // [ISODCL(133, 140)]; /* 733 */
	u32 type_l_path_table; // [ISODCL(141, 144)]; /* 731 */
	char opt_type_l_path_table[ISODCL(145, 148)]; /* 731 */
	char type_m_path_table[ISODCL(149, 152)]; /* 732 */
	char opt_type_m_path_table[ISODCL(153, 156)]; /* 732 */
	char root_directory_record[ISODCL(157, 190)]; /* 9.1 */
	char volume_set_id[ISODCL(191, 318)]; /* dchars */
	char publisher_id[ISODCL(319, 446)]; /* achars */
	char preparer_id[ISODCL(447, 574)]; /* achars */
	char application_id[ISODCL(575, 702)]; /* achars */
	char copyright_file_id[ISODCL(703, 739)]; /* 7.5 dchars */
	char abstract_file_id[ISODCL(740, 776)]; /* 7.5 dchars */
	char bibliographic_file_id[ISODCL(777, 813)]; /* 7.5 dchars */
	char creation_date[ISODCL(814, 830)]; /* 8.4.26.1 */
	char modification_date[ISODCL(831, 847)]; /* 8.4.26.1 */
	char expiration_date[ISODCL(848, 864)]; /* 8.4.26.1 */
	char effective_date[ISODCL(865, 881)]; /* 8.4.26.1 */
	char file_structure_version[ISODCL(882, 882)]; /* 711 */
	char unused4[ISODCL(883, 883)];
	char application_data[ISODCL(884, 1395)];
	char unused5[ISODCL(1396, 2048)];
};

struct iso_path_table {
	unsigned char  name_len[2];	/* 721 */
	char extent[4];			/* 731 */
	char  parent[2];		/* 721 */
	char name[254];
};

#define	LEN_ISONAME		31
#define	MAX_ISONAME_V1		37
#define	MAX_ISONAME_V2		207		/* 254 - 33 - 14 (XA Record) */
#define	MAX_ISONAME_V2_RR	193		/* 254 - 33 - 28 (CE Record) */
#define	MAX_ISONAME_V2_RR_XA	179		/* 254 - 33 - 14 - 28	    */
#define	MAX_ISONAME		MAX_ISONAME_V2	/* Used for array space defs */
#define	MAX_ISODIR		254		/* Must be even and <= 255   */

struct iso_directory_record {
	unsigned char length[ISODCL(1, 1)];  /* 711 */
	char ext_attr_length[ISODCL(2, 2)];  /* 711 */
	char extent[ISODCL(3, 10)]; /* 733 */
	char size[ISODCL(11, 18)]; /* 733 */
	char date[ISODCL(19, 25)]; /* 7 by 711 */
	unsigned char flags[ISODCL(26, 26)];
	char file_unit_size[ISODCL(27, 27)]; /* 711 */
	char interleave[ISODCL(28, 28)]; /* 711 */
	char volume_sequence_number[ISODCL(29, 32)]; /* 723 */
	unsigned char name_len[ISODCL(33, 33)]; /* 711 */
	char name[MAX_ISONAME + 1]; /* Not really, but we need something here */
};

struct iso_info {
	std::vector<u8> game_id;
	iso_primary_descriptor voldes;
	std::vector<iso_path_table> pathtables;
	iso_directory_record *rootdir;
};

namespace fs {

	struct iso_device : device_base
	{	
		std::string iso_path;
		fs::file file;
		iso_info *drive_info;

		iso_device(std::string iso);
		~iso_device();

		bool stat(const std::string& path, stat_t& info);
		bool statfs(const std::string& path, device_stat& info);
		bool remove_dir(const std::string& path);
		bool create_dir(const std::string& path);
		bool rename(const std::string& from, const std::string& to);
		bool remove(const std::string& path);
		bool trunc(const std::string& path, u64 length);
		bool utime(const std::string& path, s64 atime, s64 mtime);

		std::unique_ptr<file_base> open(const std::string& path, bs_t<open_mode> mode);
		std::unique_ptr<dir_base> open_dir(const std::string& path);

	protected:
		std::tuple<u32, stat_t> find_extent(const std::string path);
	};

	struct iso_stream : file_base
	{
		fs::file iso;
		std::unique_ptr<DiscIO::DriveReader> m_drivereader;
		size_t pos = 0;
		bool isDrive;
		std::vector<DiscRegion> regions;

		iso_stream::iso_stream(std::string path)
		{
			if (fs::is_file(path)) {
				iso.open(path);
				isDrive = false;
			}
			else if (cdio_is_cdrom(path)) {
				m_drivereader = std::make_unique<DiscIO::DriveReader>(path);
				isDrive = true;
			}
			else {
				fmt::throw_exception("iso_stream: path is neither an ISO or a Blu-Ray drive.");
				return;
			}

			char hasEncryption;
			seek(3952, fs::seek_set);
			read(&hasEncryption, 1); // Read (possible) 3K3Y header
			if (hasEncryption != 68) {
				// Determine number of encrypted regions
				be_t<u32> numRegions = 0;
				seek(0, fs::seek_set);
				read(&numRegions, sizeof(int));
				be_t<u32> startsector;
				seek(8, fs::seek_set);
				read(&startsector, sizeof(u32));
			
				bool isEncrypted = false;
				for (int i = 0; i < numRegions * 2 - 1; i++) {
					be_t<u32> nextsector;
					read(&nextsector, sizeof(u32));
					regions.emplace_back(DiscRegion(startsector, nextsector, isEncrypted));
					isEncrypted = !isEncrypted;
					startsector = nextsector;
				}
			}
		}

		~iso_stream() override
		{
		}

		stat_t stat() override
		{
			stat_t stat;
			stat.is_directory = false;
			stat.is_writable = false;
			stat.size = size();
			return stat;
		}

		bool trunc(u64 length) override
		{
			fmt::throw_exception("iso_stream: trunc() not implemented.");
		}

		u64 iso_stream::read(void* buffer, u64 size)
		{
			bool encrypted = false;
			for (auto region : regions) {
				if ((pos > region.startSector*2048) && (pos <= region.nextSector*2048)) {
					encrypted = region.encrypted;
					break;
				}
			}
			if (encrypted) {
				/*size_t buf_offset = pos - (pos % 2048);
				size_t buf_size = size - (size % 2048) + 2048;
				std::vector<u8> temp(buf_size);

				if (isDrive) {
					m_drivereader->Read(pos, size, (u8*)temp.data());
				}
				else {
					iso.seek(pos);
					iso.read(temp, size);
				}

				// decryption goes here

				memcpy_s(buffer, size, temp.data() + (pos - buf_offset), size);*/

				fmt::throw_exception("No ISO decryption support yet.");
			}

			if (isDrive) {
				m_drivereader->Read(pos, size, (u8*)buffer);
				pos += size;
				return size;
			}
			else {
				iso.seek(pos);
				size_t real_size = iso.read(buffer, size);
				pos += real_size;
				return real_size;
			}
		}

		u64 write(const void* buffer, u64 size) override
		{
			// ignore writes
			fmt::raw_error("iso_stream: write() not allowed.");
			return 0;
		}

		u64 seek(s64 offset, seek_mode whence) override
		{
			switch (whence) {
			case fs::seek_set:
				pos = offset;
				break;
			case fs::seek_cur:
				pos += offset;
				break;
			case fs::seek_end:
				pos = size() - offset;
				break;
			}

			if (isDrive)
				return pos;
			else
				return iso.seek(offset, whence);
		}

		u64 iso_stream::size()
		{
			if (isDrive)
				return m_drivereader->GetRawSize();
			else
				return iso.size();
		}
	};

}