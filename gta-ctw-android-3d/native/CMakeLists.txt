cmake_minimum_required(VERSION 3.22)
project(ctw_android_3d_mod LANGUAGES C CXX)

add_library(ctw_mod SHARED
    src/ctw_mod.cpp
)

target_include_directories(ctw_mod PRIVATE include)
target_compile_features(ctw_mod PRIVATE cxx_std_17)
target_compile_options(ctw_mod PRIVATE -Wall -Wextra -Werror)
