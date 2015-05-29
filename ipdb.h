#ifndef IPDB_IP_H_
#define IPDB_IP_H_

#include <stdint.h>
#include <string>

class IPDB {
 public:
  explicit IPDB(const char* filename);
  ~IPDB();

  std::string Find(const std::string& ip) const;

 private:
  IPDB(const IPDB&);

  uint32_t IP2Long(const std::string& ip) const;

  int fd_;
  size_t size_;
  void* m_;
  uint32_t offset_;
};

#endif // IPDB_IP_H_
