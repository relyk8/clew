# **********************************************************
# Clew Channel 3 -- cmplog DynamoRIO client build
#
# Modeled on the DynamoRIO 11.91.20651 samples/CMakeLists.txt build pattern
# (find_package(DynamoRIO) / configure_DynamoRIO_client / use_DynamoRIO_extension).
#
# MSVC ONLY: DynamoRIO's DynamoRIOConfig.cmake hard-fails (FATAL_ERROR, ~L561-564)
# if the compiler is not MSVC, so this cannot be configured or built on Linux.
# Build it on Windows. See BUILD_RECIPE.md.
#
# Intended 32-bit build (from a "x86 Native Tools" VS prompt or with -A Win32):
#   cmake -G "Ninja" ^
#         -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
#         -DDynamoRIO_DIR=C:\dynamorio-sdk\cmake ^
#         <path-to-this-dir>
#   cmake --build . --target cmplog
# (Ninja from an x86 tools prompt yields a 32-bit build; with the VS generator
#  pass -A Win32. The DynamoRIO_DIR must point at the *dev kit's* cmake/ dir, not
#  the lean runtime-only C:\dynamorio deployed to the analysis guest.)
# **********************************************************

cmake_minimum_required(VERSION 3.14)

project(clew_cmplog C)

# Point this at the dev kit's cmake/ directory, either with
# -DDynamoRIO_DIR=<kit>\cmake or by setting DYNAMORIO_HOME. There is no default:
# a wrong one silently builds against the wrong headers.
if (NOT DEFINED DynamoRIO_DIR AND DEFINED ENV{DYNAMORIO_HOME})
  set(DynamoRIO_DIR "$ENV{DYNAMORIO_HOME}/cmake"
      CACHE PATH "DynamoRIO installation's cmake directory")
endif ()

find_package(DynamoRIO 11.91)
if (NOT DynamoRIO_FOUND)
  message(FATAL_ERROR "DynamoRIO 11.91 package required to build cmplog")
endif ()

# MSVC client cflags borrowed from samples/CMakeLists.txt: disable stack-guard
# (___security_cookie unresolved in a client) and quiet benign warnings.
if (WIN32)
  set(CL_CFLAGS "/GS- /wd4100 /wd4127 /wd4054")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CL_CFLAGS}")
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif ()

add_library(cmplog SHARED cmplog.c)
configure_DynamoRIO_client(cmplog)

# Minimal extension set: cmplog.c only uses drmgr (TLS field, thread + bb
# instrumentation events). No drreg/drutil/drx/droption are used.
use_DynamoRIO_extension(cmplog drmgr)
