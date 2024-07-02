#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>


struct ResultCString {
  enum class Tag {
    Ok,
    Err,
  };

  struct Ok_Body {
    char *_0;
  };

  struct Err_Body {
    char *_0;
  };

  Tag tag;
  union {
    Ok_Body ok;
    Err_Body err;
  };
};

using DuckDBMallocFunctionType = void*(*)(size_t);

using DuckDBFreeFunctionType = void(*)(void*);


extern "C" {

/// Hash a varchar using the specified hashing algorithm.
ResultCString hashing_varchar(const char *hash_name,
                              size_t hash_name_len,
                              const char *content,
                              size_t len);

/// Create a HMAC using the specified hash function and key.
ResultCString hmac_varchar(const char *hash_name,
                           size_t hash_name_len,
                           const char *key,
                           size_t key_len,
                           const char *content,
                           size_t len);

void init_memory_allocation(DuckDBMallocFunctionType malloc_fn, DuckDBFreeFunctionType free_fn);

} // extern "C"
