# **********************************************************
# Clew Channel 3 -- drtrace DynamoRIO client build
#
# Modeled on the DynamoRIO 11.91.20651 samples/CMakeLists.txt build pattern
# (find_package(DynamoRIO) / configure_DynamoRIO_client / use_DynamoRIO_extension).
#
# MSVC ONLY: DynamoRIO's DynamoRIOConfig.cmake hard-fails (FATAL_ERROR, ~L561-564)
# if the compiler is not MSVC. This cannot be configured/built on the Linux host;
# build it inside the win10_dev Windows snapshot. See BUILD_RECIPE.md.
#
# Intended 32-bit build (from a "x86 Native Tools" VS prompt or with -A Win32):
#   cmake -G "Ninja" ^
#         -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
#         -DDynamoRIO_DIR=C:\dynamorio-sdk\cmake ^
#         <path-to-this-dir>
#   cmake --build . --target drtrace
# (Ninja from an x86 tools prompt yields a 32-bit build; with the VS generator
#  pass -A Win32. DynamoRIO_DIR must point at the *dev kit's* cmake/ dir, not the
#  lean runtime-only C:\dynamorio deployed to the analysis guest.)
# **********************************************************

cmake_minimum_required(VERSION 3.14)

project(clew_drtrace C)

# Default to the durable dev-kit copy on the Linux host; override on the guest
# with -DDynamoRIO_DIR=<pushed-kit>\cmake .
if (NOT DEFINED DynamoRIO_DIR)
  set(DynamoRIO_DIR "/home/relyk8/dr-sdk/DynamoRIO-Windows-11.91.20651/cmake"
      CACHE PATH "DynamoRIO installation's cmake directory")
endif ()

find_package(DynamoRIO 11.91)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO 11.91 package required to build drtrace")
endif ()

# MSVC client cflags borrowed from samples/CMakeLists.txt: disable stack-guard
# (___security_cookie unresolved in a client) and quiet benign warnings.
if (WIN32)
  set(CL_CFLAGS "/GS- /wd4100 /wd4127 /wd4054")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CL_CFLAGS}")
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif ()

add_library(drtrace SHARED drtrace.c)
configure_DynamoRIO_client(drtrace)

# api_table.h is generated next to drtrace.c by scripts/gen_api_table.py, so the
# source dir must be on the include path even for an out-of-tree build.
target_include_directories(drtrace PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# drmgr: TLS field, thread + bb instrumentation + module load events.
# drwrap: the API wrapping that makes Channel 3 a candidate producer.
# No drreg/drutil/drx/droption/drcontainers are used -- the hit-cap table is a
# fixed open-addressed array in drtrace.c precisely to avoid another extension,
# since every added extension is another way the guest build can fail.
use_DynamoRIO_extension(drtrace drmgr)
use_DynamoRIO_extension(drtrace drwrap)
