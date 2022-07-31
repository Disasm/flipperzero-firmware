#include <furi.h>
#include <furi_hal.h>
#include <storage/storage.h>
#include <lib/toolbox/stream/file_stream.h>
#include <elf.h>

#define TAG "elfloader"
#define ELF_PATH EXT_PATH("rustapp.elf")

int32_t elf_loader_app(void* p) {
    int32_t rc = 0;
    uint8_t* app_memory = 0;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    //Stream* stream = file_stream_alloc(storage);
    Stream* stream = file_stream_alloc(storage);
    furi_record_close(RECORD_STORAGE);

    if (!file_stream_open(stream, ELF_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        FURI_LOG_E(TAG, "can't open ELF file %s", ELF_PATH);
        goto err;
    }

    uint8_t buffer[256] __attribute__ ((aligned (16)));
    size_t len = stream_read(stream, buffer, sizeof(buffer));
    if (len != sizeof(buffer)) {
        FURI_LOG_E(TAG, "can't read ELF header");
        goto err;
    }

    Elf32_Ehdr* ehdr = (Elf32_Ehdr*)buffer;

    // Perform some basic checks.
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        FURI_LOG_E(TAG, "wrong ELF signature");
        goto err;
    }
    if ((ehdr->e_type != ET_EXEC) || (ehdr->e_machine != EM_ARM)) {
        FURI_LOG_E(TAG, "wrong ELF type or target machine");
        goto err;
    }

    uint32_t phend = ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum;
    if (phend > sizeof(buffer)) {
        // Headers are too large, we don't support this.
        FURI_LOG_E(TAG, "headers are too big");
        goto err;
    }
    if ((ehdr->e_phoff & 3) != 0) {
        // Unaligned header.
        FURI_LOG_E(TAG, "unaligned program header");
        goto err;
    }
    if (ehdr->e_phentsize != sizeof(Elf32_Phdr)) {
        // Sanity check.
        FURI_LOG_E(TAG, "program header size mismatch");
        goto err;
    }

    // Process program headers.
    Elf32_Phdr* phdr = (Elf32_Phdr*)(&buffer[ehdr->e_phoff]);
    uint32_t min_address = 0xffffffff;
    uint32_t max_address = 0;
    for (uint32_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            uint32_t start_address = phdr[i].p_vaddr;
            uint32_t end_address = phdr[i].p_vaddr + phdr[i].p_memsz;
            if (start_address < min_address) {
                min_address = start_address;
            }
            if (end_address > max_address) {
                max_address = end_address;
            }
        }
    }

    uint32_t load_size = max_address - min_address;
    FURI_LOG_I(TAG, "load size: %u", load_size);
    if (load_size > 0x10000) {
        // 64KB is enough for everyone.
        FURI_LOG_E(TAG, "virtual memory area is too large");
        goto err;
    }

    app_memory = malloc(load_size);
    if (app_memory == 0) {
        // Memory allocation failed.
        FURI_LOG_E(TAG, "memory allocation failed");
        goto err;
    }

    FURI_LOG_I(TAG, "allocated memory: 0x%08x", (uint32_t)app_memory);
    if ((((uint32_t)app_memory) & 3) != 0) {
        FURI_LOG_E(TAG, "allocated memory is not 4-byte aligned");
        goto err;
    }


    for (uint32_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            FURI_LOG_I(TAG, "loading segment %u...", i);
            if (!stream_seek(stream, phdr[i].p_offset, StreamOffsetFromStart)) {
                FURI_LOG_E(TAG, "section %u seek failed", i);
                goto err;
            }

            uint32_t offset = phdr[i].p_vaddr - min_address;
            FURI_LOG_I(TAG, "segment %u offset: %u", i, offset);
            if (!stream_read(stream, app_memory + offset, phdr[i].p_filesz)) {
                FURI_LOG_E(TAG, "section %u read failed", i);
                goto err;
            }

            // Pad with zeros if needed.
            if (phdr[i].p_memsz > phdr[i].p_filesz) {
                memset(app_memory + offset + phdr[i].p_filesz, 0, phdr[i].p_memsz - phdr[i].p_filesz);
            }
        }
    }
    FURI_LOG_I(TAG, "segments loaded");

    uint32_t entry_point_offset = ehdr->e_entry - min_address;
    FuriThreadCallback entry_point = (FuriThreadCallback)(app_memory + entry_point_offset);
    FURI_LOG_I(TAG, "calling entry point: 0x%08x", (uint32_t)entry_point);
    rc = (entry_point)(p);

err:
    file_stream_close(stream);
    stream_free(stream);
    if (app_memory != 0) free(app_memory);

    return rc;
}
