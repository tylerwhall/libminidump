/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef fooformathfoo
#define fooformathfoo

#include <inttypes.h>

__attribute__((packed)) struct minidump_header {
        uint32_t signature;
        uint32_t version;
        uint32_t number_of_streams;
        uint32_t stream_directory_rva;
        uint32_t checksum;
        uint32_t time_date_stamp;
        uint64_t flags;
};

enum {
        MINIDUMP_NORMAL                            = 0x00000000,
        MINIDUMP_WITH_DATA_SEGS                    = 0x00000001,
        MINIDUMP_WITH_FULL_MEMORY                  = 0x00000002,
        MINIDUMP_WITH_HANDLE_DATA                  = 0x00000004,
        MINIDUMP_FILTER_MEMORY                     = 0x00000008,
        MINIDUMP_SCAN_MEMORY                       = 0x00000010,
        MINIDUMP_WITH_UNLOADED_MODULES             = 0x00000020,
        MINIDUMP_WITH_INDIRECTLY_REFERENCED_MEMORY = 0x00000040,
        MINIDUMP_FILTER_MODULE_PATHS               = 0x00000080,
        MINIDUMP_WITH_PROCESS_THREAD_DATA          = 0x00000100,
        MINIDUMP_WITH_PRIVATE_READ_WRITE_MEMORY    = 0x00000200,
        MINIDUMP_WITHOUT_OPTIONAL_DATA             = 0x00000400,
        MINIDUMP_WITH_FULL_MEMORY_INFO             = 0x00000800,
        MINIDUMP_WITH_THREAD_INFO                  = 0x00001000,
        MINIDUMP_WITH_CODE_SEGS                    = 0x00002000,
        MINIDUMP_WITHOUT_AUXILIARY_STATE           = 0x00004000,
        MINIDUMP_WITH_FULL_AUXILIARY_STATE         = 0x00008000,
        MINIDUMP_WITH_PRIVATE_WRITE_COPY_MEMORY    = 0x00010000,
        MINIDUMP_IGNORE_INACCESSIBLE_MEMORY        = 0x00020000,
        MINIDUMP_WITH_TOKEN_INFORMATION            = 0x00040000
};

__attribute__((packed)) struct minidump_location_descriptor {
        uint32_t data_size;
        uint32_t rva;
};

__attribute__((packed)) struct minidump_directory {
        uint32_t stream_type;
        struct minidump_location_descriptor location;
};

enum {
        MINIDUMP_UNUSED_STREAM                = 0,
        MINIDUMP_RESERVED_STREAM_0            = 1,
        MINIDUMP_RESERVED_STREAM_1            = 2,
        MINIDUMP_THREAD_LIST_STREAM           = 3,
        MINIDUMP_MODULE_LIST_STREAM           = 4,
        MINIDUMP_MEMORY_LIST_STREAM           = 5,
        MINIDUMP_EXCEPTION_STREAM             = 6,
        MINIDUMP_SYSTEM_INFO_STREAM           = 7,
        MINIDUMP_THREAD_EX_LIST_STREAM        = 8,
        MINIDUMP_MEMORY_64_LIST_STREAM        = 9,
        MINIDUMP_COMMENT_STREAM_A             = 10,
        MINIDUMP_COMMENT_STREAM_W             = 11,
        MINIDUMP_HANDLE_DATA_STREAM           = 12,
        MINIDUMP_FUNCTION_TABLE_STREAM        = 13,
        MINIDUMP_UNLOADED_MODULE_LIST_STREAM  = 14,
        MINIDUMP_MISC_INFO_STREAM             = 15,
        MINIDUMP_MEMORY_INFO_LIST_STREAM      = 16,
        MINIDUMP_THREAD_INFO_LIST_STREAM      = 17,
        MINIDUMP_HANDLE_OPERATION_LIST_STREAM = 18,

        MINIDUMP_LAST_RESERVED_STREAM         = 0xffff,

        /* Breakpad extensions -- 0x4767 = "Gg" */
        MINIDUMP_BREAKPAD_INFO_STREAM         = 0x47670001,
        MINIDUMP_ASSERTION_INFO_STREAM        = 0x47670002,

        /* Breakpad/Linux extensions */
        MINIDUMP_LINUX_CPU_INFO               = 0x47670003,
        MINIDUMP_LINUX_PROC_STATUS            = 0x47670004,
        MINIDUMP_LINUX_LSB_RELEASE            = 0x47670005,
        MINIDUMP_LINUX_CMD_LINE               = 0x47670006,
        MINIDUMP_LINUX_ENVIRON                = 0x47670007,
        MINIDUMP_LINUX_AUXV                   = 0x47670008,
        MINIDUMP_LINUX_MAPS                   = 0x47670009,
        MINIDUMP_LINUX_DSO_DEBUG              = 0x4767000A,

        /* libminidump extensions */
        MINIDUMP_LINUX_OS_RELEASE             = 0x4c500001,
        MINIDUMP_LINUX_EXE                    = 0x4c500002,
        MINIDUMP_LINUX_COMM                   = 0x4c500003,
        MINIDUMP_LINUX_PRPSINFO               = 0x4c500004,
        MINIDUMP_LINUX_COREDUMP_EHDR          = 0x4c500005
};


#endif
