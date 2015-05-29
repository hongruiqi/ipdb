#include "ipdb.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

IPDB::IPDB(const char* filename)
{
  fd_ = open(filename, O_RDWR);
  if (fd_<0) {
    throw std::runtime_error(strerror(errno));
  }
  struct stat buf;
  bzero(&buf, sizeof(buf));
  if (fstat(fd_, &buf)<0) {
    close(fd_);
    throw std::runtime_error(strerror(errno));
  }
  size_ = buf.st_size;
  m_ = mmap(0, size_, PROT_READ|PROT_WRITE, MAP_SHARED, fd_, 0);
  if (!m_) {
    close(fd_);
    throw std::runtime_error(strerror(errno));
  }
  offset_ = be32toh(*(uint32_t*)m_);
}

IPDB::~IPDB()
{
  if (m_&&munmap(m_, size_)<0) {
    perror("munmap");
  };
  if (fd_>=0&&close(fd_)<0) {
    perror("close");
  }
}

std::string IPDB::Find(const std::string& ip) const
{
  uint32_t nip = IP2Long(ip);
  const char* index = (char*)m_ + 4;
  uint32_t start = le32toh(*(uint32_t*)(index + (nip >> 24)*4));
  const uint32_t* q = (uint32_t*)(index + 1024) + start*2;
  const uint32_t* limit = (uint32_t*)((char*)m_ + offset_ - 1024);
  for (; q<limit; q+=2) {
    if (be32toh(*q) >= nip) {
      uint32_t t = le32toh(*(q + 1));
      uint32_t d_offset = t & 0x00FFFFFF;
      uint8_t d_len = t >> 24;
      const char* r = (char*)m_ + offset_ + d_offset - 1024;
      return std::string(r, d_len);
    }
  }
  throw std::runtime_error("invalid ip");
}

uint32_t IPDB::IP2Long(const std::string& ip) const
{
  uint32_t nip = 0;
  size_t prev = -1;
  for (int i=0; i<4; i++) {
    size_t pos = ip.find(".", prev+1);
    if ((pos==-1&&i<3) || (pos!=-1&&i==3)) {
      throw std::runtime_error("invalid ip");
    }
    pos = pos!=-1?pos:ip.length();
    int x = atoi(ip.substr(prev+1, pos-prev-1).c_str());
    if ((x&~0xFF)!=0) {
      throw std::runtime_error("invalid ip");
    }
    nip <<= 8;
    nip |= x & 0xFF;
    prev = pos;
  }
  return nip;
}
