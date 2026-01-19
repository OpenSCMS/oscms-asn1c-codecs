# Copyright (c) 2025 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.
#
# SPDX-License-Identifier: Apache-2.0

# Enforce out-of-source builds
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(
    FATAL_ERROR
      "In-source builds are not allowed. Please create a build directory and run CMake from there.\n"
      "You will need to remove CMakeCache.txt and CMakeFiles/ to clean up the generated files."
  )
endif()

# Ensure one of the two acceptable build types are selected: DEBUG or RELEASE.
# Default to DEBUG
if(NOT CMAKE_BUILD_TYPE)
  # No build type specified, default to Debug and force it into the cache
  message(STATUS "No build type specified, defaulting to Debug")
  set(CMAKE_BUILD_TYPE
      Debug
      CACHE STRING "Build type" FORCE)
else()
  # Check they chose an acceptable one
  set(valid_build_types "Debug" "Release")
  list(FIND valid_build_types ${CMAKE_BUILD_TYPE} _index)
  if(${_index} EQUAL -1)
    message(
      FATAL_ERROR
        "Unknown build type ${CMAKE_BUILD_TYPE}. Supported build types are Debug and Release"
    )
  endif()
  unset(valid_build_types)
endif()

cmake_minimum_required(VERSION 3.28.3)
project(
  OscmsApi
  VERSION 1.0.0
  LANGUAGES C CXX) # CXX added for testig support

# set cmake build options
option(BUILD_TESTS "Build unit tests" ON)
option(RUN_CPPCHECK "Enable cppcheck" ON)
option(ENABLE_ASN1C_DEBUG "Enable ASN1C DEBUG output in the generated code" OFF)

# set compiler flags Standard compile options
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED TRUE)
set(C_EXTENSIONS ON) # Enable gnu11
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CXX_EXTENSIONS ON) # Enable gnu11

# Enforce C compiler minimum version of 11 (which is what comes with Ubuntu
# 22.04). CI jobs actually use gcc:12
#
# C++ is only used for unit tests, so we don't care about its version

if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_C_COMPILER_VERSION VERSION_LESS 11)
    message(
      FATAL_ERROR
        "C compiler version must be at least 11.0.0, you are running ${CMAKE_C_COMPILER_VERSION}. Please update your C compiler.\n"
        "You will need to remove CMakeCache.txt and CMakeFiles/ to clean up the generated files."
    )
  endif()
else()
  message(
    FATAL_ERROR
      "C compiler must be GNU, version >= 11. Please update your C compiler.\n"
      "You will need to remove CMakeCache.txt and CMakeFiles/ to clean up the generated files."
  )
endif()

if(BUILD_TESTS)
  # Set up for unit testing using googletest
  include(FetchContent)

  # Disable installation of googletest into the install tree
  set(INSTALL_GTEST
      OFF
      CACHE BOOL "" FORCE)

  # Disable installation of gmock
  set(INSTALL_GMOCK
      OFF
      CACHE BOOL "" FORCE)

  # Download and unpack googletest at configure time
  FetchContent_Declare(
    googletest # Specify the commit you depend on and update it regularly.
    URL https://github.com/google/googletest/archive/refs/tags/v1.16.0.zip)

  # For Windows: Prevent overriding the parent project's compiler/linker
  # settings
  set(gtest_force_shared_crt
      ON
      CACHE BOOL "" FORCE)

  # Add googletest directly to our build. This adds the following targets: *
  # gtest * gtest_main
  FetchContent_MakeAvailable(googletest)
  # FetchContent_MakeAvailable(googlemock)

  # Enable unit testing
  enable_testing()

  include(GoogleTest)

  set(MEMORYCHECK_COMMAND_OPTIONS
      "--tool=memcheck --leak-check=full --num-callers=50 --show-reachable=yes ${EXTRA_MEMCHECK_OPTIONS}"
  )
  include(CTest)
endif()

# Find cppcheck
if(RUN_CPPCHECK)
  find_program(CPPCHECK cppcheck)
  if(NOT CPPCHECK)
    message(WARNING "cppcheck not found. Disabling cppcheck.")
    set(RUN_CPPCHECK OFF)
  else()
    message(STATUS "Found cppcheck: ${CPPCHECK}")
    set(CPPCHECK_OPTIONS
        --language=c
        --inline-suppr
        --platform=unix64
        --enable=all
        "--suppressions-list=${PROJECT_SOURCE_DIR}/.cppcheck-suppress"
        --force
        --error-exitcode=1)
  endif()
endif()

# Build the common API source
add_subdirectory(submodules/api)

# add source files
file(GLOB CODEC_SOURCES "src/*.c" CMAKE_CONFIGURE_DEPENDS)
file(GLOB GENERATED_SOURCES
     "submodules/asn1c-generated/oscms_asn1c_generated/*.c"
     CMAKE_CONFIGURE_DEPENDS)

add_library(oscms_codecs_api STATIC ${CODEC_SOURCES} ${GENERATED_SOURCES})
target_link_libraries(oscms_codecs_api
                      PUBLIC "$<LINK_LIBRARY:WHOLE_ARCHIVE,oscms_api_common>")

# We have to specify both root and generated include paths as the skeletons used
# in generated the code use chevrons in their include statements.
target_include_directories(
  oscms_codecs_api
  PRIVATE submodules/asn1c-generated
  PRIVATE submodules/asn1c-generated/oscms_asn1c_generated)

# These definitions prevent the compilation of code related to all the unwanted
# encoding schemes.
#
# This is not only a nice code-size reduction but is also required as we don't
# generate any of the support code for them.
target_compile_definitions(
  oscms_codecs_api
  PRIVATE -DASN_DISABLE_APER_SUPPORT -DASN_DISABLE_BER_SUPPORT
          -DASN_DISABLE_JER_SUPPORT -DASN_DISABLE_UPER_SUPPORT
          -DASN_DISABLE_XER_SUPPORT)

# Specify `-DENABLE_ASN1C_DEBUG` to enable ASN1C DEBUG output.
#
# This is only useful for debugging, so it is not enabled by default and
# produces a *lot* of output.
if(ENABLE_ASN1C_DEBUG)
  target_compile_definitions(oscms_codecs_api PUBLIC -DASN_EMIT_DEBUG=1)
endif()

# Enable thread safety for the obvious reasons (and because ASN_EMIT_DEBUG won't
# compile without it)
target_compile_definitions(oscms_codecs_api PUBLIC -DASN_THREAD_SAFE)

target_compile_options(
  oscms_codecs_api
  PRIVATE -Wall
          -Wextra
          --pedantic
          -fPIC
          $<IF:$<CONFIG:Debug>,-O0,-O2>
          $<IF:$<CONFIG:Debug>,-g,>
          -fvisibility=hidden
          -Werror
          -Wno-unused-function # Because we're a library
          -Wno-unused-parameter
          -Wno-unused-const-variable
          -Wno-missing-field-initializers # Helps when only initializing one
                                          # variant of a Union
          -Wno-variadic-macros # Needed to compile the debug code
)

if(RUN_CPPCHECK)
  message(STATUS "Adding cppcheck custom command")
  # we use a custom command to ensure that cppcheck is run after the build, sees
  # all the source files at once, and stops the build if there are errors

  add_custom_command(
    TARGET oscms_codecs_api
    POST_BUILD
    COMMAND
      "${CPPCHECK}" ARGS "${CPPCHECK_OPTIONS}"
      # Don't analyze geenerated code
      -i"${PROJECT_SOURCE_DIR}/submodules/asn1c-generated"
      "$<JOIN:$<TARGET_PROPERTY:oscms_codecs_api,INCLUDE_DIRECTORIES>,;-I>"
      ${CODEC_SOURCES}
    COMMENT "Running cppcheck"
    COMMAND_EXPAND_LISTS)
endif()

# Bring in the Unit tests
if(BUILD_TESTS)
  add_subdirectory(tests)
endif()
