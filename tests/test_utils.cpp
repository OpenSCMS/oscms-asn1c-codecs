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

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#include "test_utils.hpp"

void hexdump(const char *heading, const void *data, std::size_t len)
{
    const char *buf = (const char *)data;
    fprintf(stderr, "\n------------------------\n%s:\n", heading ? heading : "No heading");
    if (len == 0 || !buf)
    {
        fprintf(stderr, "(empty)\n");
        return;
    }

    char ascii[17] = {0};

    size_t i;
    for (i = 0; i < len; i++)
    {
        if (i % 16 == 0)
        {
            if (i != 0)
                fprintf(stderr, "|%-16s|\n", ascii);
            strcpy(ascii, "                ");
            fprintf(stderr, "%04zx ", i);
        }

        fprintf(stderr, "%02x ", buf[i] & 0xff);
        if (isprint(buf[i]))
            ascii[i % 16] = buf[i];
        else
            ascii[i % 16] = '.';
    }

    if (len % 16 != 0)
    {
        while (i % 16 != 0)
        {
            fprintf(stderr, "   ");
            i++;
        }

        fprintf(stderr, "|%-16s|\n", ascii);
    }
    fprintf(stderr, "\n\n");
}

int read_binary_test_file(const char *filename, std::vector<uint8_t> &file_data)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        fprintf(stderr, "Could not open test file: %s\n", filename);
        return -1;
    }

    file_data.resize(std::filesystem::file_size(filename));
    file.read((char *)file_data.data(), file_data.size());
    file.close();
    return 0;
}
