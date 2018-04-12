# standalone_libghthash
Standalone libghthash for use in embedded systems.
All credit goes to Simon Kagstrom for making this library.
All I did was make a standalone version of it.

See the original library at: https://github.com/SimonKagstrom/libghthash

INTRODUCTION:
The Generic Hash Table (GHT) is a hash table that should be
extensible, generic and clean (codewise). You can store any kind of
data with it and, specify hash functions (or write your own) and
specify heuristics to use (like transposing touched elements).

USAGE
To use the library, add
  #include <ght_hash_table.h>

to your source-file and add libghthash.lib to your project
