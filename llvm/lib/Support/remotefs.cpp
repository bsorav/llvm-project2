#include <sstream>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <string>
#include <set>
#include <unordered_set>
#include <map>
#include <unordered_map>

#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Infos.hpp>
#include <curlpp/Options.hpp>
#include <curlpp/Exception.hpp>

#include "llvm/ADT/SmallString.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/remotefs.h"

#include "support/debug.h"
#include "support/utils.h"

using namespace std;

static char const* serverURL = nullptr;
static char const* dirPath = nullptr;
static const char* const server_url_path = "/api/eqchecker/submit_eqcheck";
static const char* const server_pathname_to_local_filename = "server_pathname_to_local_filename";
//static const char* const commandGetClientFileStatus = "getClientFileStatus";
//static const char* const commandGetClientFileContents = "getClientFileContents";
//static const char* const cmdSpecifier = "serverCommand";
//static const char* const pathnameSpecifier = "dirPath";

void
remotefs_activate(std::string const& url, std::string const& dir)
{
  if (!url.empty()) {
    serverURL = strdup((url + server_url_path).c_str());
  }
  if (!dir.empty()) {
    dirPath = strdup(dir.c_str());
  }
}

bool
remotefs_active()
{
  return serverURL != nullptr && dirPath != nullptr;
}

static bool
perform_request(std::string const& url, std::string const& jsonRequest, std::string& response_str)
{
  try {
    curlpp::Easy request;

    std::cout << "url = " << url << std::endl;
    request.setOpt(new curlpp::options::Url(url));  //set the url
    request.setOpt(new curlpp::options::PostFields(jsonRequest));
    request.setOpt(new curlpp::options::PostFieldSize(jsonRequest.length()));

    // Headers
    std::list<std::string> headers;
    headers.push_back("Content-Type: application/json");
    headers.push_back("Accept: application/json");

    request.setOpt(new curlpp::options::HttpHeader(headers));

    std::ostringstream response;

    request.setOpt(new curlpp::options::WriteStream(&response)); //response target

    request.perform(); //executes the GET request, blocking till response recvd

    long ResponseCode = curlpp::infos::ResponseCode::get(request);
    if (ResponseCode != 200) {
      std::cerr << "Response code " << ResponseCode << ", returning false." << std::endl;
      return false;
    }
    response_str = response.str();
    //std::cout << "response = " << response.str() << std::endl;
    return true;
  } catch (curlpp::LogicError& e) {
    std::cerr << e.what() << std::endl;
    return false;
  } catch (curlpp::RuntimeError& e) {
    std::cerr << e.what() << std::endl;
    return false;
  }
}

static std::string
get_pathname_at_dirPath(std::string const& filename)
{
  llvm::SmallString<256> ret(dirPath);
  llvm::sys::path::append(ret, filename);
  return ret.str().str();
}

static std::string
get_mapping_file_pathname()
{
  return get_pathname_at_dirPath(server_pathname_to_local_filename);
}

static bool
get_mapped_local_pathname(std::string const& pathname, std::string& local_pathname)
{
  std::ifstream mapping_file(get_mapping_file_pathname());
  if (!mapping_file) {
    return false;
  }

  std::string server_pathname;
  std::string local_filename;
  while (mapping_file >> std::quoted(server_pathname) >> std::quoted(local_filename)) {
    if (server_pathname != pathname) {
      continue;
    }

    std::string candidate = get_pathname_at_dirPath(local_filename);
    std::ifstream local_file(candidate, std::ios::binary);
    if (!local_file) {
      NOT_REACHED();
      return false;
    }
    local_pathname = candidate;
    return true;
  }
  return false;
}

static bool
add_mapped_local_filename(std::string const& pathname, std::string const& local_filename)
{
  std::ofstream mapping_file(get_mapping_file_pathname(), std::ios::app);
  if (!mapping_file) {
    return false;
  }
  mapping_file << std::quoted(pathname) << ' ' << std::quoted(local_filename) << '\n';
  return mapping_file.good();
}

static remotefs_file_type_t
get_type_from_string(string const& s)
{
  if (s == "file") return file;
  if (s == "directory") return directory;
  if (s == "other") return other;
  //llvm::errs() << _FNLN_ << ": s = " << s << "\n";
  NOT_REACHED();
}

//returns true if success
bool
remotefs_get_status(std::string const& pathname, remotefs_file_status_t& status)
{
  std::ostringstream url_stream;
  url_stream << serverURL; // << "/?" << cmdSpecifier << "=" << commandGetClientFileStatus << "&" << pathnameSpecifier << "=" << curlpp::escape(pathname);
  std::string url = url_stream.str();

  std::string jsonRequest = R"({
    "serverCommand": "getClientFileStatus",
    "dirPath":")" + pathname + R"("
  })";


  std::string response;
  if (!perform_request(url, jsonRequest, response)) {
    return false;
  }
  vector<string> response_sections = splitOnChar(response, '\n');
  std::cout << _FNLN_ << ": response = " << response << "\n";
  std::cout << _FNLN_ << ": response_sections.size() = " << response_sections.size() << "\n";
  if (response_sections.size() != 9) {
    return false;
  }
  status.m_accessible = string_to_bool(response_sections[0]);
  status.m_type = get_type_from_string(response_sections[1]);
  status.m_mode = static_cast<mode_t>(std::stoul(response_sections[2], nullptr, 16));
  status.m_size = string_to_int(response_sections[3]);
  status.m_user = string_to_int(response_sections[4]);
  status.m_group = string_to_int(response_sections[5]);
  status.m_device = string_to_int(response_sections[6]);
  status.m_file = string_to_int(response_sections[7]);

  std::string const& mod = response_sections[8];
  struct tm tm = {};
  char* res = strptime(mod.c_str(), "%Y-%m-%dT%H:%M:%S", &tm);
  status.m_last_modified_time.tv_sec = 0;
  status.m_last_modified_time.tv_nsec = 0;
  if (res) {
    time_t secs = timegm(&tm); // timegm: UTC as in ISO8601
    status.m_last_modified_time.tv_sec = secs;

    //Parse .NNNZ for fractional seconds
    char const* subsec = strchr(mod.c_str(), '.');
    if (subsec) {
      int millis = 0;
      sscanf(subsec, ".%3d", &millis);
      status.m_last_modified_time.tv_nsec = millis * 1'000'000;
    }
  }

  std::cout << "status = " << status.m_accessible << " " << status.m_type << " " << status.m_mode << " " << status.m_size << " " << status.m_user << " " << status.m_group << " " << status.m_device << " " << status.m_file << " " << status.m_last_modified_time.tv_sec << " " << status.m_last_modified_time.tv_nsec << std::endl;

  return true;
}

//returns true if success
bool
remotefs_get_local_pathname(std::string const& pathname, std::string& local_pathname)
{
  if (get_mapped_local_pathname(pathname, local_pathname)) {
    return true;
  }

  std::ostringstream url_stream;
  url_stream << serverURL; // << "/?" << cmdSpecifier << "=" << commandGetClientFileContents << "&" << pathnameSpecifier << "=" << curlpp::escape(pathname);
  std::string url = url_stream.str();

  std::string jsonRequest = R"({
    "serverCommand": "getClientFileContents",
    "dirPath":")" + pathname + R"("
  })";


  std::string response;
  if (!perform_request(url, jsonRequest, response)) {
    return false;
  }

  std::string local_filename = llvm::sys::path::filename(pathname).str();
  if (local_filename.empty()) {
    return false;
  }

  local_pathname = get_pathname_at_dirPath(local_filename);
  std::ofstream local_file(local_pathname, std::ios::binary);
  if (!local_file) {
    return false;
  }
  local_file.write(response.data(), response.size());
  local_file.close();
  if (!local_file.good()) {
    return false;
  }

  return add_mapped_local_filename(pathname, local_filename);
}
