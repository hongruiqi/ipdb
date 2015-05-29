#include "ipdb.h"
#include <iostream>
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

IPDB::IPDB(const char* filename) {
  fd_ = open(filename, O_RDWR);
  if (fd_ < 0) {
    throw std::runtime_error(strerror(errno));
  }
  struct stat buf;
  bzero(&buf, sizeof(buf));
  if (fstat(fd_, &buf) < 0) {
    close(fd_);
    throw std::runtime_error(strerror(errno));
  }
  size_ = buf.st_size;
  m_ = mmap(0, size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0);
  if (!m_) {
    close(fd_);
    throw std::runtime_error(strerror(errno));
  }
  offset_ = be32toh(*(uint32_t*)m_);
}

IPDB::~IPDB() {
  if (m_ && munmap(m_, size_) < 0) {
    perror("munmap");
  };
  if (fd_ >= 0 && close(fd_) < 0) {
    perror("close");
  }
}

std::string IPDB::Find(const std::string& ip) const {
  uint32_t nip = IP2Long(ip);
  const char* index = (char*)m_ + 4;
  uint8_t top = nip >> 24;
  uint64_t* start =
      (uint64_t*)(index + 1024) + le32toh(*(uint32_t*)(index + top * 4));
  uint64_t* end = top != 255
                      ? (uint64_t*)(index + 1024) +
                            le32toh(*(uint32_t*)(index + (top + 1) * 4))
                      : (uint64_t*)((char*)m_ + offset_ - 1024);
  while (start < end) {
    uint64_t* mid = start + (end - start) / 2;
    uint32_t _ip = be32toh(*(uint32_t*)mid);
    if (_ip > nip) {
      end = mid;
    } else if (_ip < nip) {
      start = mid + 1;
    } else {
      start = end = mid;
    }
  }
  uint32_t t = le32toh(*((uint32_t*)start + 1));
  uint32_t d_offset = t & 0x00FFFFFF;
  uint8_t d_len = t >> 24;
  const char* r = (char*)m_ + offset_ + d_offset - 1024;
  return std::string(r, d_len);
  throw std::runtime_error("invalid ip");
}

uint32_t IPDB::IP2Long(const std::string& ip) const {
  uint32_t nip = 0;
  size_t prev = -1;
  for (int i = 0; i < 4; i++) {
    size_t pos = ip.find(".", prev + 1);
    if ((pos == -1 && i < 3) || (pos != -1 && i == 3)) {
      throw std::runtime_error("invalid ip");
    }
    pos = pos != -1 ? pos : ip.length();
    if (pos - prev - 1 > 3) {
      throw std::runtime_error("invalid ip");
    }
    int x = 0;
    for (prev++; prev != pos; prev++) {
      if (ip[prev] < '0' || ip[prev] > '9') {
        throw std::runtime_error("invalid ip");
      }
      x *= 10;
      x += ip[prev] - '0';
    }
    if ((x & ~0xFF) != 0) {
      throw std::runtime_error("invalid ip");
    }
    nip <<= 8;
    nip |= x & 0xFF;
  }
  return nip;
}
