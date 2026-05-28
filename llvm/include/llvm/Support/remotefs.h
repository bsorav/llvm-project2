#pragma once

#include <string>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>

enum remotefs_file_type_t {
  file, directory, other
};

struct remotefs_file_status_t {
  bool m_accessible;
  uint64_t m_device;
  uint64_t m_file;
  uint32_t m_user;
  uint32_t m_group;
  uint64_t m_size;
  struct timespec m_last_modified_time;
  enum remotefs_file_type_t m_type;
  mode_t m_mode;
};

void remotefs_activate(std::string const& url, std::string const& dir);
bool remotefs_active();
bool remotefs_get_status(std::string const& pathname, remotefs_file_status_t& status); //returns true if success
bool remotefs_get_local_pathname(std::string const& pathname, std::string& local_pathname); //returns true if success
