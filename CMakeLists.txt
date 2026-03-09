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

cmake_minimum_required(VERSION 3.28.3)
project(
  OscmsAsn1cCodecs
  VERSION 1.0.0
  LANGUAGES C CXX) # CXX added for testing support

# Pull in the CMake helpers module
include(FetchContent)
FetchContent_Declare(
  oscms_cmake_helpers
  GIT_REPOSITORY https://github.com/OpenSCMS/oscms-cmake-helpers.git
  GIT_TAG main)
FetchContent_MakeAvailable(oscms_cmake_helpers)

oscms_enable_cppcheck()
oscms_enable_testing()

# set additional cmake build options
option(ENABLE_ASN1C_DEBUG "Enable ASN1C DEBUG output in the generated code" OFF)

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
      # Don't analyze generated code
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
