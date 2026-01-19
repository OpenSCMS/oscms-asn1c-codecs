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

# Set up to copy the data directory
add_custom_target(
  copy_data ALL
  COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different
          ${CMAKE_CURRENT_SOURCE_DIR}/data ${CMAKE_CURRENT_BINARY_DIR}/data
  COMMENT "Copying data directory"
  VERBATIM)

# Build the tests executable
file(GLOB SOURCES CONFIGURE_DEPENDS "*.cpp")

add_executable(asn1c_codecs_tests ${SOURCES})
add_dependencies(asn1c_codecs_tests copy_data)

target_link_libraries(asn1c_codecs_tests oscms_codecs_api GTest::gtest_main
                      gmock_main)

target_include_directories(
  asn1c_codecs_tests
  PRIVATE ${PROJECT_SOURCE_DIR}/submodules/asn1c-generated
  PRIVATE ${PROJECT_SOURCE_DIR}/submodules/asn1c-generated/oscms_asn1c_generated
  PRIVATE ${PROJECT_SOURCE_DIR}/src)

target_compile_options(asn1c_codecs_tests PRIVATE -std=c++17 -g -O0 -fPIC)

add_test(NAME asn1c_codecs_tests COMMAND asn1c_codecs_tests)

# file(GLOB TEST_JSON CONFIGURE_DEPENDS "*.json") file(GLOB TEST_CSV
# CONFIGURE_DEPENDS "*.csv") file(GLOB TEST_TXT CONFIGURE_DEPENDS "*.txt")

# foreach(TEST_FILE ${TEST_JSON} ${TEST_CSV} ${TEST_TXT}) cmake_path(GET
# TEST_FILE FILENAME TEST_BASENAME) message(STATUS "Configuring TEST FILE:
# ${TEST_BASENAME}") configure_file(${TEST_BASENAME} ${TEST_BASENAME} COPYONLY)
# endforeach()

gtest_discover_tests(asn1c_codecs_tests)
