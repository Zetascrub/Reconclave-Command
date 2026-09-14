# Header-only canonical brand identity (palette, strings). Generated from
# identity.json by tools/generate_identity.py.
add_library(reconclave_identity INTERFACE)
target_include_directories(reconclave_identity INTERFACE include)
target_compile_features(reconclave_identity INTERFACE cxx_std_17)
