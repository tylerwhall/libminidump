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
        MINIDUMP_THREAD_LIST_STREAM           = 3,           /* TODO XXXX */
        MINIDUMP_MODULE_LIST_STREAM           = 4,           /* TODO XXXX */
        MINIDUMP_MEMORY_LIST_STREAM           = 5,           /* TODO XXXX */
        MINIDUMP_EXCEPTION_STREAM             = 6,           /* TODO XXXX */
        MINIDUMP_SYSTEM_INFO_STREAM           = 7,           /* done */
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
        MINIDUMP_LINUX_CPU_INFO               = 0x47670003,  /* done */
        MINIDUMP_LINUX_PROC_STATUS            = 0x47670004,  /* done */
        MINIDUMP_LINUX_LSB_RELEASE            = 0x47670005,  /* done */
        MINIDUMP_LINUX_CMD_LINE               = 0x47670006,  /* done */
        MINIDUMP_LINUX_ENVIRON                = 0x47670007,  /* done */
        MINIDUMP_LINUX_AUXV                   = 0x47670008,  /* done */
        MINIDUMP_LINUX_MAPS                   = 0x47670009,  /* done */
        MINIDUMP_LINUX_DSO_DEBUG              = 0x4767000A,  /* TODO XXXX */

        /* libminidump extensions */
        MINIDUMP_LINUX_OS_RELEASE             = 0x4c500001,
        MINIDUMP_LINUX_EXE                    = 0x4c500002,  /* done */
        MINIDUMP_LINUX_COMM                   = 0x4c500003,  /* done */
        MINIDUMP_LINUX_PRPSINFO               = 0x4c500004,  /* done */
        MINIDUMP_LINUX_CORE_EHDR              = 0x4c500005,  /* done */
        MINIDUMP_LINUX_ATTR_CURRENT           = 0x4c500006,  /* done */
};

__attribute__((packed)) struct minidump_system_info {
        uint16_t processor_architecture;
        uint16_t processor_level;
        uint16_t processor_revision;
        uint8_t number_of_processors;
        uint8_t product_type;
        uint32_t major_version;
        uint32_t minor_version;
        uint32_t build_number;
        uint32_t platform_id;
        uint32_t csd_version_rva;
        uint16_t suite_mask;
        uint16_t reserved2;
        union {
                struct {
                        uint32_t vendor_id[3];
                        uint32_t version_information;
                        uint32_t feature_information;
                        uint32_t amd_extended_cpu_features;
                } x86_cpu_info;
                struct {
                        uint64_t processor_features[2];
                } other_cpu_info;
        } cpu;
};

enum {
        MINIDUMP_PROCESSOR_ARCHITECTURE_INTEL = 0,
        MINIDUMP_PROCESSOR_ARCHITECTURE_MIPS = 1,
        MINIDUMP_PROCESSOR_ARCHITECTURE_PPC = 3,
        MINIDUMP_PROCESSOR_ARCHITECTURE_ARM = 5,
        MINIDUMP_PROCESSOR_ARCHITECTURE_IA64 = 6,
        MINIDUMP_PROCESSOR_ARCHITECTURE_AMD64 = 9,

        /* Breakpad extension */
        MINIDUMP_PROCESSOR_ARCHITECTURE_SPARC = 0x8001
};

enum {
        MINIDUMP_PLATFORM_WIN32S        = 0,
        MINIDUMP_PLATFORM_WIN32_WINDOWS = 1,
        MINIDUMP_PLATFORM_WIN32_NT      = 2,
        MINIDUMP_PLATFORM_WIN32_CE      = 3,

        /* Breakpad extensions */
        MINIDUMP_PLATFORM_LINUX         = 0x8201
};

__attribute__((packed)) struct minidump_vs_fixed_file_info {
        uint32_t signature;
        uint32_t struct_version;
        uint32_t file_version_hi;
        uint32_t file_version_lo;
        uint32_t product_version_hi;
        uint32_t product_version_lo;
        uint32_t file_flags_mask;    /* Identifies valid bits in fileFlags */
        uint32_t file_flags;
        uint32_t file_os;
        uint32_t file_type;
        uint32_t file_subtype;
        uint32_t file_date_hi;
        uint32_t file_date_lo;
};

__attribute__((packed)) struct minidump_module {
        uint64_t base_of_image;
        uint32_t size_of_image;
        uint32_t check_sum;
        uint32_t time_date_stamp;
        uint32_t module_name_rva;
        struct minidump_vs_fixed_file_info version_info;
        struct minidump_location_descriptor cv_record;
        struct minidump_location_descriptor misc_record;
        uint64_t reserved0;
        uint64_t reserved1;
};

__attribute__((packed)) struct minidump_module_list {
        uint32_t number_of_modules;
        struct minidump_module modules[];
};

__attribute__((packed)) struct minidump_memory_descriptor{
        uint64_t start_of_memory_range;
        struct minidump_location_descriptor memory;
};

__attribute__((packed)) struct minidump_thread {
        uint32_t thread_id;
        uint32_t suspend_count;
        uint32_t priority_class;
        uint32_t priority;
        uint64_t teb;
        struct minidump_location_descriptor thread_context;
        struct minidump_memory_descriptor stack;
};

__attribute__((packed)) struct minidump_thread_list {
        uint32_t number_of_threads;
        struct minidump_thread threads[];
};

__attribute__((packed)) struct minidump_memory_list {
        uint32_t number_of_memory_ranges;
        struct minidump_memory_descriptor memory_ranges[];
};

__attribute__((packed)) struct minidump_exception {
        uint32_t exception_code;
        uint32_t exception_flags;
        uint64_t exception_record;
        uint64_t exception_address;
        uint32_t number_parameters;
        uint32_t _alignment;
        uint64_t exception_information[15];
};

__attribute__((packed)) struct minidump_exception_stream {
        uint32_t thread_id;
        uint32_t _alignment;
        struct minidump_exception exception_record;
        struct minidump_location_descriptor thread_context;
};

__attribute__((packed)) struct minidump_xmm_save_area32_amd64 {
        uint16_t control_word;
        uint16_t status_word;
        uint8_t tag_word;
        uint8_t reserved1;
        uint16_t error_opcode;
        uint32_t error_offset;
        uint16_t error_selector;
        uint16_t reserved2;
        uint32_t data_offset;
        uint16_t data_selector;
        uint16_t reserved3;
        uint32_t mx_csr;
        uint32_t mx_csr_mask;
        __uint128_t float_registers[8];
        __uint128_t xmm_registers[16];
        uint8_t reserved4[96];
};

__attribute__((packed)) struct minidump_context_amd64 {
        uint64_t  p1_home;
        uint64_t  p2_home;
        uint64_t  p3_home;
        uint64_t  p4_home;
        uint64_t  p5_home;
        uint64_t  p6_home;
        uint32_t  context_flags;
        uint32_t  mx_csr;

        uint16_t  cs;
        uint16_t  ds;
        uint16_t  es;
        uint16_t  fs;
        uint16_t  gs;
        uint16_t  ss;
        uint32_t  eflags;
        uint64_t  dr0;
        uint64_t  dr1;
        uint64_t  dr2;
        uint64_t  dr3;
        uint64_t  dr6;
        uint64_t  dr7;
        uint64_t  rax;
        uint64_t  rcx;
        uint64_t  rdx;
        uint64_t  rbx;
        uint64_t  rsp;
        uint64_t  rbp;
        uint64_t  rsi;
        uint64_t  rdi;
        uint64_t  r8;
        uint64_t  r9;
        uint64_t  r10;
        uint64_t  r11;
        uint64_t  r12;
        uint64_t  r13;
        uint64_t  r14;
        uint64_t  r15;
        uint64_t  rip;

        union {
                struct minidump_xmm_save_area32_amd64 flt_save;
                struct {
                        __uint128_t header[2];
                        __uint128_t legacy[8];
                        __uint128_t xmm0;
                        __uint128_t xmm1;
                        __uint128_t xmm2;
                        __uint128_t xmm3;
                        __uint128_t xmm4;
                        __uint128_t xmm5;
                        __uint128_t xmm6;
                        __uint128_t xmm7;
                        __uint128_t xmm8;
                        __uint128_t xmm9;
                        __uint128_t xmm10;
                        __uint128_t xmm11;
                        __uint128_t xmm12;
                        __uint128_t xmm13;
                        __uint128_t xmm14;
                        __uint128_t xmm15;
                } sse_registers;
        };

        __uint128_t vector_register[26];
        uint64_t vector_control;
        uint64_t debug_control;
        uint64_t last_branch_to_rip;
        uint64_t last_branch_from_rip;
        uint64_t last_exception_to_rip;
        uint64_t last_exception_from_rip;
};

enum {
        MINIDUMP_CONTEXT_AMD64 = 0x00100000,
        MINIDUMP_CONTEXT_AMD64_CONTROL = (MINIDUMP_CONTEXT_AMD64 | 0x00000001),
        MINIDUMP_CONTEXT_AMD64_INTEGER = (MINIDUMP_CONTEXT_AMD64 | 0x00000002),
        MINIDUMP_CONTEXT_AMD64_SEGMENTS = (MINIDUMP_CONTEXT_AMD64 | 0x00000004),
        MINIDUMP_CONTEXT_AMD64_FLOATING_POINT = (MINIDUMP_CONTEXT_AMD64 | 0x00000008),
        MINIDUMP_CONTEXT_AMD64_DEBUG_REGISTERS = (MINIDUMP_CONTEXT_AMD64 | 0x00000010),
        MINIDUMP_CONTEXT_AMD64_XSTATE = (MINIDUMP_CONTEXT_AMD64 | 0x00000040),
        MINIDUMP_CONTEXT_AMD64_FULL = (MINIDUMP_CONTEXT_AMD64_CONTROL |
                                       MINIDUMP_CONTEXT_AMD64_INTEGER |
                                       MINIDUMP_CONTEXT_AMD64_FLOATING_POINT),
        MINIDUMP_CONTEXT_AMD64_ALL = (MINIDUMP_CONTEXT_AMD64_FULL |
                                      MINIDUMP_CONTEXT_AMD64_SEGMENTS |
                                      MINIDUMP_CONTEXT_AMD64_DEBUG_REGISTERS)
};

__attribute__((packed)) struct minidump_string {
        uint32_t length;
        uint16_t buffer[];
};

#endif
