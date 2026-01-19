// Copyright (c) 2025 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#ifndef TEST_UTILS_HPP
#define TEST_UTILS_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

#include "oscms_codecs_api/octet_buffer.h"

class TrackedOctetBuffer
{
  private:
    OscmsOctetBuffer buffer;

  public:
    TrackedOctetBuffer()
    {
        oscms_octet_buffer_init(&buffer);
    }

    ~TrackedOctetBuffer()
    {
        oscms_empty_octet_buffer(&buffer);
    }

    size_t length() const
    {
        return buffer.length;
    }

    uint8_t *data()
    {
        return buffer.data;
    }

    operator OscmsOctetBuffer *()
    {
        return &buffer;
    }
};

void hexdump(const char *heading, const void *data, std::size_t len);

int read_binary_test_file(const char *filename, std::vector<uint8_t> &file_data);

#endif
