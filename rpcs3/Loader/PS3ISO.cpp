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

DiscRegion::DiscRegion(size_t startSector, size_t nextSector, bool encrypted) 
	: startSector(startSector), nextSector(nextSector), encrypted(encrypted) 
{

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

	// Returns extent, is dir, size
	// Returns true if extent is dir, returns false if extent is file
	std::tuple<u32,stat_t> iso_device::find_extent(const std::string path)
	{
		auto path_dirs = fmt::split(path, { "/", "\\" });
		int numfound = 1;
		int i = 1;
		u16 parent = 1;
		while (numfound < path_dirs.size()) {
			if (*(u16*)&drive_info->pathtables[i].parent == parent) {
				if (drive_info->pathtables[i].name == path_dirs[numfound]) {
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
				while (true) {
					file.read(&dir_rec, 33);
					if (dir_rec.length[0] == 0)
						break;
					file.read(&dir_rec.name, dir_rec.length[0]-33);
					auto temp1 = fmt::split(std::string(dir_rec.name), { ";" });
					if ((temp1.size() > 0) && (temp1[0] == path_dirs[numfound])) {
						stat_t stat;
						stat.is_directory = std::bitset<8>(dir_rec.flags[0])[1];
						stat.is_writable = false;
						stat.atime = stat.mtime = stat.ctime = iso_time_to_time(dir_rec.date);
						stat.size = *(u32*)&dir_rec.size;
						return { *(u32*)&dir_rec.extent, stat };
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
				return{ *(u32*)&drive_info->pathtables[i].extent, stat };
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
			return std::make_unique<file_view>(std::make_unique<iso_stream>(iso_path), (size_t)extent * 2048, stat.size);
		else
			return std::unique_ptr<file_base>();
	}

	std::unique_ptr<dir_base> iso_device::open_dir(const std::string & path)
	{
		return std::unique_ptr<dir_base>();
	}
	
	
}