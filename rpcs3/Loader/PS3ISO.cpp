#include "stdafx.h"
#include "Utilities\File.h"

#include "PS3ISO.h"
#include "Utilities\CDUtils.h"
#include "Crypto\utils.h"
#include "Utilities\StrUtil.h"

#include <algorithm>
#include <bitset>
#include <time.h>
#include <vector>

static std::unordered_map<std::string, iso_info>  drive_info_map; // TODO: Mutex?

static s64 iso_time_to_time(char date[7]) {
	tm time;
	time.tm_year = date[0];
	time.tm_mon = date[1];
	time.tm_mday = date[2];
	time.tm_hour = date[3];
	time.tm_min = date[4];
	time.tm_sec = date[5];
	time.tm_isdst = 0;
	return mktime(&time);
}

namespace fs {

	iso_device::iso_device(std::string iso) : iso_path(iso)
	{
		file.reset(std::make_unique<iso_stream>(iso));
		auto it = drive_info_map.find(iso);
		drive_info = &drive_info_map[iso];
		std::vector<u8> temp_id(32);
		file.seek(2064);
		file.read(temp_id);
		if ((it == drive_info_map.end()) || (it->second.game_id != temp_id)) { // Drive was not in map or other disk inserted, fill with info
			drive_info->game_id = temp_id;
			file.seek(32768);
			file.read(drive_info->voldes); // Read primary volume descriptor
			int pathtable_size = drive_info->voldes.path_table_size.l;
			int pathtable_curoffset = 0;
			while(pathtable_curoffset < pathtable_size) { // Read in path tables
				iso_path_table table;
				memset(&table, 0, sizeof(iso_path_table));
				file.seek(drive_info->voldes.type_l_path_table*2048+pathtable_curoffset);
				file.read(&table, 8);
				file.read(&table.name, table.name_len[0]);
				drive_info->pathtables.push_back(table);
				pathtable_curoffset += 8 + (table.name_len[0] + (table.name_len[0] % 2));
			}
			drive_info->rootdir = (iso_directory_record*)&drive_info->voldes.root_directory_record;
		}
	}

	iso_device::~iso_device()
	{

	}

	bool iso_device::need_ird() {
		char hasEncryption;
		file.seek(3952);
		file.read(hasEncryption);
		return (hasEncryption != 68) && (hasEncryption != 69);
	}

	void iso_device::set_ird(fs::file ird_file) {
		constexpr size_t BUFSIZE = 8 * 1024; // Decompress IRD
		std::vector<u8> tempin = ird_file.to_vector<u8>();
		u8 tempbuf[BUFSIZE];
		std::vector<u8> out;
		z_stream strm;
		strm.zalloc = Z_NULL;
		strm.zfree = Z_NULL;
		strm.opaque = Z_NULL;
		strm.avail_in = ird_file.size();
		strm.avail_out = BUFSIZE;
		strm.next_in = &tempin[0];
		strm.next_out = tempbuf;
		int ret = inflateInit2(&strm, 32 + MAX_WBITS);

		while (strm.avail_in)
		{
			ret = inflate(&strm, Z_NO_FLUSH);
			if (ret == Z_STREAM_END)
				break;
			if (ret != Z_OK)
				fmt::throw_exception("Error while decompressing IRD file!");

			if (!strm.avail_out) {
				out.insert(out.end(), &tempbuf[0], &tempbuf[BUFSIZE]);
				strm.next_out = tempbuf;
				strm.avail_out = BUFSIZE;
			}
			else
				break;
		}

		int inflate_res = Z_OK;
		inflate_res = inflate(&strm, Z_FINISH);

		if (inflate_res != Z_STREAM_END)
			fmt::throw_exception("Error while decompressing IRD file!");

		out.insert(out.end(), &tempbuf[0], &tempbuf[BUFSIZE - strm.avail_out]);
		inflateEnd(&strm);

		std::array<u8, 16> disc_key;
		// Generate disc key
		for (int i = (out.size() - 40); i < (out.size() - 24); i++)
		{
			disc_key[(i - (out.size() - 40))] = out[i];
		}
		drive_info->disc_key = disc_key;
		file.reset(std::make_unique<iso_stream>(iso_path, disc_key));
	}

	std::string iso_device::get_game_id()
	{
		auto id = std::string((char*)drive_info->game_id.data(), 
			std::find(drive_info->game_id.begin(), drive_info->game_id.end(), ' ') - drive_info->game_id.begin());
		id.erase(std::remove(id.begin(), id.end(), '-'), id.end());
		return id;
	}

	// Returns extent, and stat_t of file or dir
	std::tuple<u32,stat_t> iso_device::find_extent(std::string path)
	{
		auto it = drive_info->extent_map.find(path);
		if (it != drive_info->extent_map.end()) {
			return drive_info->extent_map[path];
		}

		auto path_dirs = fmt::split(path, { "/", "//", "\\" });

		if (path_dirs.size() == 1) {
			//This is a request for the root dir
			stat_t stat;
			stat.is_directory = true;
			stat.is_writable = false;
			return{ 1, stat };
		}

		int numfound = 1;
		int i = 1;
		u16 parent = 1;
		while (numfound < path_dirs.size()) {
			if ((i < drive_info->pathtables.size()) && (*(u16*)&drive_info->pathtables[i].parent == parent)) {
				if (stricmp(drive_info->pathtables[i].name,path_dirs[numfound].c_str()) == 0) {
					parent = i+1;
					i++;
					numfound++;
					while (*(u16*)&drive_info->pathtables[i].parent < parent) { // skip folders which belong to parent dir
						i++;
					}
				}
				else {
					i++;
					continue;
				}
			}
			else { // We have run out of pathtables which have our current parent as parent, what we are looking for may be a file
				u32 dirextent = *(u32*)&drive_info->pathtables[parent - 1].extent;
				iso_directory_record dir_rec;
				file.seek(dirextent * 2048);
				file.read(&dir_rec, 33);
				file.seek(dir_rec.length[0] - 33, fs::seek_cur);
				u32 dirlength = *(u32*)&dir_rec.size;
				u32 dirpos = dirextent * 2048;
				while (file.pos() < dirpos+dirlength) {
					file.read(&dir_rec, 33);
					if (dir_rec.length[0] == 0) { // The next entry did not fit entirely in the current sector, skip to next sector.
						u64 pos = file.pos() - 33;
						file.seek(pos + (2048 - (pos % 2048)));
						continue;
					}
					file.read(&dir_rec.name, dir_rec.length[0]-33);
					auto temp1 = fmt::split(std::string(dir_rec.name), { ";" });
					if ((temp1.size() > 0) && (stricmp(temp1[0].c_str(), path_dirs[numfound].c_str()) == 0)) {
						stat_t stat;
						stat.is_directory = std::bitset<8>(dir_rec.flags[0])[1];
						stat.is_writable = false;
						stat.atime = stat.mtime = stat.ctime = iso_time_to_time(dir_rec.date);
						stat.size = *(u32*)&dir_rec.size;
						std::tuple<u32, stat_t> result = { *(u32*)&dir_rec.extent, stat };
						drive_info->extent_map[path] = result;
						return result;
					}
				}
				break;
			}
			if (numfound == path_dirs.size()) {
				iso_directory_record dir_rec;
				file.seek(*(u32*)&drive_info->pathtables[i].extent * 2048);
				file.read(&dir_rec, 33);
				stat_t stat;
				stat.is_directory = true;
				stat.is_writable = false;
				stat.atime = stat.mtime = stat.ctime = iso_time_to_time(dir_rec.date);
				stat.size = *(u32*)&dir_rec.size;
				std::tuple<u32, stat_t> result = { *(u32*)&drive_info->pathtables[i].extent, stat };
				drive_info->extent_map[path] = result;
				return result;
			}
			while (path_dirs[numfound] == ".") {
				numfound++;
				i = parent+1;
			}
			while (path_dirs[numfound] == "..") {
				numfound++;
				parent = *(u16*)&drive_info->pathtables[i].parent;
				parent = *(u16*)&drive_info->pathtables[parent-1].parent;
				i = parent;
				while (*(u16*)&drive_info->pathtables[i].parent < parent) { // skip folders which belong to parent dir
					i++;
				}
			}
		}
		stat_t stat;
		return{ 0, stat };
	}

	bool iso_device::stat(const std::string & path, stat_t & info)
	{
		u32 extent;
		stat_t stat;
		std::tie(extent, stat) = find_extent(path);
		if (extent) {
			info = stat;
			return true;
		}
		return false;
	}

	bool iso_device::statfs(const std::string & path, device_stat & info)
	{
		info.avail_free = 0;
		info.block_size = 2048;
		info.total_free = 0;
		info.total_size = file.size();
		return true;
	}

	bool iso_device::remove_dir(const std::string & path)
	{
		return false;
	}

	bool iso_device::create_dir(const std::string & path)
	{
		return false;
	}

	bool iso_device::rename(const std::string & from, const std::string & to)
	{
		return false;
	}

	bool iso_device::remove(const std::string & path)
	{
		return false;
	}

	bool iso_device::trunc(const std::string & path, u64 length)
	{
		return false;
	}

	bool iso_device::utime(const std::string & path, s64 atime, s64 mtime)
	{
		return false;
	}

	std::unique_ptr<file_base> iso_device::open(const std::string & path, bs_t<open_mode> mode)
	{
		u32 extent;
		stat_t stat;
		std::tie(extent, stat) = find_extent(path);
		if ((extent > 0) && !stat.is_directory)
			return std::make_unique<file_view>(std::make_unique<iso_stream>(iso_path, drive_info->disc_key), (size_t)extent * 2048, stat.size);
		else
			return std::unique_ptr<file_base>();
	}

	std::unique_ptr<dir_base> iso_device::open_dir(const std::string & path)
	{
		return std::unique_ptr<dir_base>();
	}
	
	
}