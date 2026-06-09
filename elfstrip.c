//=================================\\
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 17
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 09.06.2026
//     PROJECT  : ELF-STRIPPER
//     PLATFORM : LINUX
//=================================\\




/* Enables GNU and Linux-specific extensions */
#define _GNU_SOURCE


/* Target signature to detect active stack unwinding 
   (C++ exceptions, Rust panics, etc.) */
#define UNWIND_SIG "_Unwind_Resume"


#define ZERO       0    // Zero out of data
#define MIN_ELF_SZ 1024 // 1 KB: Min size for strip ELF


/* Check for error sentinel */
#define IS_FAIL(e) ((e) == -1)


/* Centralized error message string constants */
#define ERR_OS(nm)     "[-] OSError: " #nm "() failed"
#define ERR_MIN_SZ     "[!] file size is below minimum ELF threshold"
#define ERR_IS_ELF     "[-] file is not valid ELF binary"
#define ERR_ELF_ST     "[-] invalid ELF-file structure"
#define ERR_ELF_TP     "[-] unsupported ELF-file type"
#define ERR_ARCH(n)    "[-] ELF-file architecture is not " #n




/* Standard integer types, string utilities,
   and ELF structures */
#include <stdint.h>
#include <string.h>
#include <elf.h>


/* POSIX System calls, file I/O,
   and memory mapping APIs */
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>




/* Represents a protected memory segment boundary */
typedef struct {  size_t start, end;  } Region_t;


/* Architecture-agnostic wrapper 
   for ELF Program Headers */
typedef union {
    Elf32_Phdr *x32; // Ptr to 32-bit header 
    Elf64_Phdr *x64; // Ptr to 64-bit header 
} Elf_Phdr;


/* Architecture-agnostic wrapper 
   for ELF Executable Headers */
typedef union {
    Elf32_Ehdr *x32; // Ptr to 32-bit executable header
    Elf64_Ehdr *x64; // Ptr to 64-bit executable header
} Elf_Ehdr;



/* Resolves the memory address 
   of the Program Header Table base */
#define PHDR_BASE(addr, offs) \
    ((void*)( (char*)(addr) + (offs) ))


/* Calculates the memory address
   of a specific Program Header entry */
#define PHDR_ADDR(base, idx, sz) \
    ((void*)( (char*)(base) + ((idx) * (sz)) ))



/* Safely initializes the architecture-agnostic header wrapper */
#define PHDR_DEF(ph, src, is_32bit) do {            \
    if (is_32bit) (ph).x32 = (Elf32_Phdr*)(src);    \
    else          (ph).x64 = (Elf64_Phdr*)(src);    \
} while (0)


/* Safely initializes the architecture-agnostic executable header wrapper */
#define EHDR_DEF(eh, src, is_32bit) do {            \
    if (is_32bit) (eh).x32 = (Elf32_Ehdr*)(src);    \
    else          (eh).x64 = (Elf64_Ehdr*)(src);    \
} while (0)


/* Safely extracts a field from the architecture-agnostic header */
#define HD_GET(hd, is_32bit, field) \
    ((is_32bit)? (hd).x32->field : (hd).x64->field)


/* Safely updates a field in the architecture-agnostic header */
#define HD_SET(hd, is_32bit, field, val) do {    \
    if (is_32bit) (hd).x32->field = (val);       \
    else          (hd).x64->field = (val);       \
} while (0)


/* Safely extracts a field from the architecture-agnostic dynamic entry */
#define DYN_GET(dp, is_32bit, field) \
    ((is_32bit)? ((Elf32_Dyn*)(dp))->field : ((Elf64_Dyn*)(dp))->field)


/* Safely updates a field in the architecture-agnostic dynamic entry */
#define DYN_SET(dp, is_32bit, field, val) do {          \
    if (is_32bit) ((Elf32_Dyn*)(dp))->field = (val);    \
    else          ((Elf64_Dyn*)(dp))->field = (val);    \
} while (0)




/* Determines if a program segment is critical 
   for execution and must be preserved */
static inline uint8_t is_crit_seg(uint32_t typ) {
    switch (typ) {
        case PT_LOAD             : // Code and Data segments
        case PT_DYNAMIC          : // Dynamic linking information
        case PT_INTERP           : // Path to the dynamic linker
        case PT_PHDR             : // Program header table 
        case PT_TLS              : // Thread-Local Storage architecture
        case PT_GNU_EH_FRAME     : // Exception unwinding frame
        case PT_GNU_STACK        : // Stack execution control (NX bit)
        case PT_GNU_RELRO        : // Read-only after relocation
        case PT_GNU_PROPERTY     : // Hardware property controls (Intel CET / IBT / SHSTK)
        case PT_ARM_EXIDX        : // ARM exception unwind tables
    #if defined(PT_RISCV_ATTRIBUTES)
        case PT_RISCV_ATTRIBUTES : // RISC-V target ISA and ABI attributes
    #endif
            return 1;
        
        default                  : // Non-critical segment (eligible for removal)
            return 0;         
    }
}




/* In-place insertion sort to order tracked regions 
   by their starting offsets */
static inline void sort_regs(Region_t *arr, size_t sz) {
    for (size_t i = 1;  i < sz;  ++i) {
        Region_t k = arr[i]; // Store the current region to be inserted
        size_t  j = i;       // Initialize the shift tracking index


        while (j && (arr[j - 1].start > k.start)) 
            // Shift larger elements forward to make room
            (arr[j] = arr[j - 1]), j--; 

        arr[j] = k; // Place the region into its sorted position
    }
}




/* Writes an error message to stderr
   and terminates the program */
static void cerr(const char *s) {
    if (s) {
        write(STDERR_FILENO, s,    strlen(s)); // Put string
        write(STDERR_FILENO, "\n", 1        ); // Put new line
    }

    /* Terminate process immediately */
    _exit(1);
}




/* Print decimal to stdout */
static void putdec(size_t num) {
    char buf[23];   // Digit buffer
    uint8_t i = 22; // Reverse cursor


    if (!num) // Zero case
        buf[i--] = '0';

    else      // Extract digits
        while (num) {
            buf[i--] = '0' + (num % 10); // Store ASCII
            num /= 10;                   // Next digit
        }
    

    write(STDOUT_FILENO, &buf[i + 1], 22 - i); // Put decimal
}




int main(int argc, char *argv[]) {
    if (argc != 2) cerr(
        "(U) elfstrip <ELF-file>\n"
        "(C) Vladislav Khudash, 2026.\n"
        "(I) Extreme ELF-file metadata stripper.\n"
        "(P) GitHub: https://github.com/vk-candpython/elfstrip\n"
        "(!) Warning: Modifies target file in-place."
    ); // Enforce correct CLI usage and display tool metadata


/*-----------------------------------------------------------------------------*/


    /* Phase 0: File initialization, validation, 
       and memory mapping for direct binary manipulation */
    int fd = open(argv[1], O_RDWR);
    if (IS_FAIL(fd)) cerr(ERR_OS(open));

    size_t fsz = 0; // Total size of the input file image



    /* Retrieve target file metadata 
       and perform basic size validation */
    { struct stat st;
    if (IS_FAIL(fstat(fd, &st)))
        cerr(ERR_OS(fstat));


    /* Enforce minimum valid size 
       threshold for ELF binaries */
    if (st.st_size < MIN_ELF_SZ)
        cerr(ERR_MIN_SZ);


    /* Set validated target file size */
    fsz = (size_t)st.st_size; }



    /* Map the target binary into the process address space
       for direct mutation */
    void *map = mmap(NULL, fsz, PROT_READ|PROT_WRITE, 
                     MAP_SHARED, fd, ZERO);
    if (map == MAP_FAILED) cerr(ERR_OS(mmap));



    /* Pointer to ELF identification array
       (EI_MAG0 to EI_NIDENT) */
    uint8_t *e_ident = (uint8_t*)map;
    

    /* Validate the ELF Magic number prefix */
    if (memcmp(e_ident, ELFMAG, SELFMAG))
        cerr(ERR_IS_ELF);


    /* Enforce Little-Endian byte ordering */
    if (e_ident[EI_DATA] != ELFDATA2LSB)
        cerr(ERR_ELF_ST);



    /*
    Detect architecture class boundaries and processing gates:
        is_32bit: 
            1 for 32-bit targets
            0 for 64-bit targets

        kep_eflg:
            1 to skip zeroing ELF header e_flags (required for ARM/ARC)
            0 to reset
    */
    uint8_t is_32bit = e_ident[EI_CLASS] == ELFCLASS32,
            kep_eflg = 0;



    /* Phase 1: Validate ELF structures 
       and extract layout metadata */
    size_t     e_phoff, e_phentsize, e_phnum;
    uint16_t   e_type;
    { uint16_t e_machine;


    /* ELF header descriptor for initial validation 
       and structural extraction */
    Elf_Ehdr eh;
    EHDR_DEF(eh, map, is_32bit);

    e_phoff     = HD_GET(eh, is_32bit, e_phoff    ); // Program headers table offset
    e_phentsize = HD_GET(eh, is_32bit, e_phentsize); // Size of single program header
    e_phnum     = HD_GET(eh, is_32bit, e_phnum    ); // Total count of program headers
    e_type      = HD_GET(eh, is_32bit, e_type     ); // ELF binary type identifier
    e_machine   = HD_GET(eh, is_32bit, e_machine  ); // Target ISA architecture


    /* Validate target as a 32-bit architecture ELF */
    if (is_32bit) {
        /* Enforce expected structure size */
        if (e_phentsize != sizeof(Elf32_Phdr))
            cerr(ERR_ELF_ST);
    }
    /* Validate target as a 64-bit architecture ELF */
    else {
        /* Enforce 64-bit class identity */
        if (e_ident[EI_CLASS] != ELFCLASS64)
            cerr(ERR_ARCH(x64));

        /* Enforce expected structure size */
        else if (e_phentsize != sizeof(Elf64_Phdr))
            cerr(ERR_ELF_ST);
    }



    /* Identify targets where e_flags
       must be preserved (ARM/AArch64 and ARC) */
    kep_eflg =
        (e_machine == EM_ARM    )
    ||  (e_machine == EM_AARCH64)
    ||  (e_machine == EM_ARC    )
#if defined(EM_ARCV2)
    ||  (e_machine == EM_ARCV2  )
#endif
    ;



    /* Enforce execution-capable binary types */
    if ((e_type != ET_EXEC) && (e_type != ET_DYN))
        cerr(ERR_ELF_TP); }



    /* Prevent integer overflows 
       during layout boundaries computation */
    size_t   phe = 0; // Program header table end offset
    { size_t bph = 0; // Total size of program header table

    if (__builtin_mul_overflow(e_phnum, e_phentsize, &bph) || 
        __builtin_add_overflow(e_phoff, bph,         &phe) || 
        (phe > fsz)
    ) cerr(ERR_ELF_ST); }



    /* Allocate an internal tracking table 
       for protected memory regions */
    size_t rgcn = 1,                                   // Initial protected region count (ELF header)
           rgsz = (rgcn + e_phnum) * sizeof(Region_t); // Buffer size for region tracking table


    Region_t *regs = (Region_t*)mmap(NULL, rgsz, PROT_READ|PROT_WRITE,
                                     MAP_PRIVATE|MAP_ANONYMOUS, -1, ZERO);
    if (regs == MAP_FAILED) cerr(ERR_OS(mmap));


    regs[0].start = 0;   // Anchor the base region at the absolute start of the file (ELF Header)
    regs[0].end   = phe; // Mark the entire Program Header Table boundary as protected



    /* Phase 2: Process, sanitize, and compact 
       program headers via polymorphic macros */
    uint16_t aphnm = 0; // Active program headers counter

    { void *phbs = PHDR_BASE(map, e_phoff); // Program header table base address

    size_t dynsz = is_32bit? // Architecture-specific dynamic entry size
        sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn);



    uint8_t has_interp = 0, // Executable has PT_INTERP (ET_EXEC or PIE)
            has_except = 0; // Active exception unwinding detected


    size_t gnu_prop_sz  = 0, // Size of PT_GNU_PROPERTY segment 
           gnu_prop_off = 0; // File offset of PT_GNU_PROPERTY segment (Intel CET)



    /*
    Combined Pre-scan: 
      - Detect execution type
      - Intel CET properties
      - targeted exception signatures
    */
    for (uint16_t j = 0;  j < e_phnum;  ++j) {
    /* Absolute address of the current program header entry */
        void *src = PHDR_ADDR(phbs, j, e_phentsize);


        /* Program header descriptor
           for pre-scan inspection */
        Elf_Phdr ph;
        PHDR_DEF(ph, src, is_32bit);

        uint32_t p_type   = HD_GET(ph, is_32bit, p_type  ); // Program segment type identifier
        size_t   p_filesz = HD_GET(ph, is_32bit, p_filesz), // Segment size within the file image
                 p_offset = HD_GET(ph, is_32bit, p_offset); // Segment offset from start of file



        /* 1. Flag binary as dynamically linked
           if interpreter path exists */
        if (p_type == PT_INTERP)
            has_interp = 1; // Exists PT_INTERP


        /* 2. Cache GNU property segment boundaries 
           for Intel CET tracking */
        else if (p_type == PT_GNU_PROPERTY) {
            gnu_prop_sz  = p_filesz; // Set property segment size metadata
            gnu_prop_off = p_offset; // Set property segment file offset
        }


        /* 3. Scan PT_LOAD for exception signature */
        else if (!has_except && (p_type == PT_LOAD) &&
                ((p_offset + p_filesz) <= fsz)
        ) {
            if (memmem(PHDR_BASE(map, p_offset), p_filesz,
                       UNWIND_SIG, sizeof(UNWIND_SIG) - 1)
            ) has_except = 1; // Exception unwinding detected
        }
    }



    /*
    Parses and filters all program headers to:
      - Validate structural integrity and mapping boundaries.
      - Drop non-essential metadata (PT_NOTE) and unused exception tables.
      - Sanitize and compact runtime linking metadata (PT_INTERP, PT_DYNAMIC).
      - Repack and shift active headers to eliminate structural gaps.
      - Register protected address intervals for downstream zeroing/truncation.
    */
    for (uint16_t i = 0;  i < e_phnum;  ++i) {
    /* Absolute address of the original source program header entry */
        void *src = PHDR_ADDR(phbs, i, e_phentsize);


        /* Mutable program header descriptor 
           for structural evaluation 
           and compaction staging */
        Elf_Phdr ph;
        PHDR_DEF(ph, src, is_32bit);

        uint32_t p_type   = HD_GET(ph, is_32bit, p_type  ); // Program segment type identifier
        size_t   p_filesz = HD_GET(ph, is_32bit, p_filesz), // Segment size within the file image
                 p_memsz  = HD_GET(ph, is_32bit, p_memsz ), // Segment image size in memory
                 p_offset = HD_GET(ph, is_32bit, p_offset); // Segment offset from start of file



        /* Catch malformed segments: memory < file */
        if (p_memsz < p_filesz)
            cerr(ERR_ELF_ST);


        /* Safeguard against integer overflow 
           and out-of-bounds mapping */
        size_t sge = 0; // Calculate & validate segment end

        if (__builtin_add_overflow(p_offset, p_filesz, &sge) ||
            (sge > fsz)
        ) continue;



        /* Precompute segment base address */
        void *segbs = PHDR_BASE(map, p_offset);



        /* Smart-sanitize PT_NOTE: Preserve Intel CET properties
           while purging metadata crumbs */
        if (p_type == PT_NOTE) {
            size_t g_end = gnu_prop_off + gnu_prop_sz, // GNU property segment upper boundary
                   p_end = p_offset     + p_filesz;    // Note segment upper boundary


            /* Wipe surrounding slack space
               if CET descriptor is nested inside */
            if (gnu_prop_sz && (gnu_prop_off >= p_offset) &&
                               (g_end        <= p_end   )
            ) {
                memset(segbs,                 ZERO, gnu_prop_off - p_offset);
                memset(PHDR_BASE(map, g_end), ZERO, p_end        - g_end   );
            }
            /* Drop entire note content if unprotected */
            else {
                memset(segbs, ZERO, p_filesz);
            }


            /* Skip appending metadata segment 
               to active headers table */
            continue;
        }
        

        /* Wipe exception tables 
           if C++ ABI is not used */
        else if (!has_except && (
                 (p_type == PT_GNU_EH_FRAME) ||
                 (p_type == PT_ARM_EXIDX   )
        )) {
            memset(segbs, ZERO, p_filesz);
            continue;
        }


        /* Anonymize trailing slack space 
           in interpreter path */
        else if (p_type == PT_INTERP) {
            char  *pt = (char*)segbs;              // Interpreter path base
            size_t ln = strnlen(pt, p_filesz) + 1; // Calc path length (incl. null)


            /* Zero out trailing bytes after 
               the null-terminated path string */
            if (ln < p_filesz) {
                memset(PHDR_BASE(pt, ln), ZERO, p_filesz - ln); // Clear slack

                HD_SET(ph, is_32bit, p_filesz, ln); // Update file size
                HD_SET(ph, is_32bit, p_memsz,  ln); // Update mem size

                p_filesz = ln;            // Sync local size
                sge      = p_offset + ln; // Refresh boundary
            }
        }


        /* Sanitize and compact
           the dynamic linking table */
        else if (p_type == PT_DYNAMIC) {
            char  *dptr = (char*)segbs; // Dynamic table base
            size_t wofs = 0;            // Compaction write offset


            /* Dual-pointer stream compaction
               to eliminate obsolete tags
               and diagnostic descriptors */
            for (
                size_t rofs = 0; // Dynamic table read offset
                (rofs + dynsz) <= p_filesz;
                rofs += dynsz
            ) {
                /* Get current entry address */
                void *s = PHDR_BASE(dptr, rofs);
                
                int64_t  tg  = DYN_GET(s, is_32bit, d_tag     ); // Get dynamic tag
                uint64_t dvl = DYN_GET(s, is_32bit, d_un.d_val); // Get dynamic value


                /* Filter and sanitize dynamic table entries */
                switch (tg) {
                    case DT_SONAME   : // Library soname, unnecessary for ET_EXEC
                        if ((e_type == ET_EXEC) || has_interp) continue;
                        break;

                    case DT_RPATH    : // Library search path (obsolete)
                    case DT_RUNPATH  : // Library search path (current)
                    case DT_DEBUG    : // Hook for runtime debuggers (e.g., GDB)
                        continue; // Always drop compiler/linker debug footprints

                    case DT_NULL     : // End-of-table sentinel marker
                    case DT_TEXTREL  : // Read-only segments relocation indicator
                    case DT_BIND_NOW : // Non-lazy runtime binding directive
                        break; // Critical markers: must be preserved even if value is ZERO

                    case DT_FLAGS    : // Dynamic flags: strip redundant linking noise
                    case DT_FLAGS_1  : // Dynamic flags (aux): strip loader/path baggage
                        dvl &= ~(
                            (tg == DT_FLAGS)?
                                DF_ORIGIN|DF_SYMBOLIC
                            :
                                DF_1_ORIGIN|DF_1_NODEFLIB|DF_1_PIE
                        );
                        if (dvl) DYN_SET(s, is_32bit, d_un.d_val, dvl);
                        /* fallthrough */

                    default          :
                        if (!dvl) continue; // Drop any other generic entry if its value is zero
                        break;
                }


                /* Shift valid entry to its final position */
                void *d = PHDR_BASE(dptr, wofs);  // Calculate target address in compacted table
                if (s != d) memmove(d, s, dynsz); // Relocate entry only if displacement is necessary
                wofs += dynsz;                    // Update write offset for next iteration


                /* Stop after writing the terminator */
                if (tg == DT_NULL) break;
            }


            /* Truncate and finalize segment sizes
               after compaction */
            if (wofs < p_filesz) {
                /* Clear trailing space left by deleted dynamic entries */
                memset(PHDR_BASE(dptr, wofs), ZERO, p_filesz - wofs);

                HD_SET(ph, is_32bit, p_filesz, wofs); // Update file size field in program header
                HD_SET(ph, is_32bit, p_memsz,  wofs); // Update memory size field in program header

                p_filesz = wofs;            // Sync local size
                sge      = p_offset + wofs; // Recalculate exact segment upper boundary offset
            }
        }



        /* Extreme PT_LOAD payload truncation
           (Convert physical zeros to virtual .bss) */
        if ((p_type == PT_LOAD) && p_filesz) {
        /* Precompute trailing memory boundary
           and initialize byte accumulator */
            uint8_t *seg_tail = (uint8_t*)PHDR_BASE(map, p_offset + p_filesz);
            size_t   bzero    = ZERO; // Reclaimed physical bytes accumulator


            /* Rewind past trailing zeros */
            while (p_filesz && !*(seg_tail - 1)) {
                p_filesz--; // Shrink file footprint
                seg_tail--; // Move tail backward
                bzero++;    // Count freed bytes
            }

            /* Recalculate exact segment upper boundary offset */
            if (bzero) sge = p_offset + p_filesz;
        }



        /* Filter, pack, and record critical 
           program headers for preservation */
        if (is_crit_seg(p_type)) {
        /* Calculate the absolute memory address 
           of the target program header entry */
            void *dst = PHDR_ADDR(phbs, aphnm, e_phentsize);


            /* Sync file size to the possibly reduced value */
            HD_SET(ph, is_32bit, p_filesz, p_filesz);

            /* Sync memory size to file size
               while preserving PT_LOAD BSS allocations */
            if ((p_type == PT_LOAD) || (p_type == PT_TLS))
                HD_SET(ph, is_32bit, p_memsz, (p_memsz > p_filesz)?
                                               p_memsz : p_filesz);
            else
                HD_SET(ph, is_32bit, p_memsz, p_filesz);


            /* Pack valid header entry to eliminate holes */
            if (src != dst) memmove(dst, src, e_phentsize);



            regs[rgcn].start = p_offset; // Save protected interval starting point
            regs[rgcn].end   = sge;      // Save protected interval ending point


        /* Advance region tracker 
           and active headers counter */
            rgcn++; aphnm++;
        }
    }



    /* Recalculate and shrink PT_PHDR dimensions 
       to reflect header compaction */
    for (uint16_t i = 0;  i < aphnm;  ++i) {
    /* Compute the destination memory address 
       for the current program header entry */
        void *dst = PHDR_ADDR(phbs, i, e_phentsize);


        /* Active program header descriptor
           for post-compaction sizing adjustments */
        Elf_Phdr phz;
        PHDR_DEF(phz, dst, is_32bit);


        /* Update PT_PHDR entry to match compacted size */
        if (HD_GET(phz, is_32bit, p_type) == PT_PHDR) {
        /* Compacted program header table size */
            size_t nwsz = aphnm * e_phentsize;

            HD_SET(phz, is_32bit, p_filesz, nwsz); // Update file size
            HD_SET(phz, is_32bit, p_memsz,  nwsz); // Update mem size 
            break;
        }
    } }



    /* Zero out the slack space left behind 
       by omitted program headers */
    if (aphnm < e_phnum) {
        size_t ddst =  e_phoff + (aphnm * e_phentsize), // Slack space start offset
               ddln = (e_phnum - aphnm) * e_phentsize;  // Slack space length

        memset(PHDR_BASE(map, ddst), ZERO, ddln);
    }



    /* Sort tracked memory regions sequentially 
       by their starting offsets 
       to prepare for the interval merging phase */
    sort_regs(regs, rgcn);



    /* Phase 3: Merge overlapping 
       or adjacent protected memory regions */
    size_t mrcn   = 0; // Index of the current merged region
    for (size_t i = 1;  i < rgcn;  ++i) {


    /* Non-contiguous region detected, push next */
        if (regs[i].start > regs[mrcn].end)
            regs[++mrcn]  = regs[i];

    /* Overlap found, expand current upper bound */
        else if (regs[i].end > regs[mrcn].end)
            regs[mrcn].end   = regs[i].end;


    } mrcn++; // Fix count of collapsed active regions



    /* Phase 4: Wipe out all unmapped gaps 
       (sections, debug symbols, strings tables) */
    { size_t pos  = regs[0].end; // Tracking pointer: end of the processed range
    for (size_t i = 1;  i < mrcn;  ++i) {


    /* Zero out gaps between protected regions
       to strip non-critical metadata */
        if (regs[i].start > pos) 
            memset(PHDR_BASE(map, pos), ZERO, regs[i].start - pos);


    /* Advance reference pointer to segment end */
        if (regs[i].end > pos)
            pos = regs[i].end;
    } }



    /* Phase 5: Destructively wipe Section Headers reference 
       and update the ELF Header via unified macro layer */

    { /* ELF header descriptor 
         to stage final structural updates */ 
    Elf_Ehdr ehf;
    EHDR_DEF(ehf, map, is_32bit);


    HD_SET(ehf, is_32bit, e_phnum,     aphnm); // Update to active program headers count
    HD_SET(ehf, is_32bit, e_shnum,     ZERO ); // Clear total section headers counter
    HD_SET(ehf, is_32bit, e_shoff,     ZERO ); // Wipe section header table file offset
    HD_SET(ehf, is_32bit, e_shentsize, ZERO ); // Zero out section header entry size
    HD_SET(ehf, is_32bit, e_shstrndx,  ZERO ); // Drop section name string table index
    
    if (!kep_eflg)
        HD_SET(ehf, is_32bit, e_flags, ZERO ); // Reset target platform processor flags
    }



    /* Anonymize standard padding bytes within e_ident */
    memset(&e_ident[EI_OSABI], ZERO, EI_NIDENT - EI_OSABI);



    /* Phase 6: Commit modified pages to storage
       and perform aggressive physical truncation */
    size_t ltsg = regs[mrcn - 1].end; // End of last active region
    
    /* Align to 8-byte boundary */
    size_t nwfsz = (ltsg + 7) & ~(size_t)7; // New file size


    /* Clear alignment padding */
    if ((nwfsz > ltsg) && (nwfsz <= fsz))
        memset(PHDR_BASE(map, ltsg), ZERO, nwfsz - ltsg);


    /* Flush memory changes to
       the file descriptor backing store */
    if (IS_FAIL(msync(map, fsz, MS_SYNC))) 
        cerr(ERR_OS(msync));


    munmap(map,  fsz ); // Unmap binary image
    munmap(regs, rgsz); // Free region tracking table memory


    /* Physically truncate the file 
       to discard all omitted trailing sections */
    if (IS_FAIL(ftruncate(fd, nwfsz))) 
        cerr(ERR_OS(ftruncate));

        
    /* Ensure metadata update is persistent */
    if (IS_FAIL(fsync(fd))) 
        cerr(ERR_OS(fsync));


    /* Close target file descriptor */
    close(fd);



    /* Calculate compression stats */
    size_t pct = ((fsz - nwfsz) * 1000) / fsz;



    /* Print final stats */
    write(STDOUT_FILENO, "[+] Stripped: ", 14);

    putdec(fsz);
    write(STDOUT_FILENO, " -> ", 4);
    putdec(nwfsz);

    
    write(STDOUT_FILENO, " bytes (-", 9);

    putdec(pct / 10);
    write(STDOUT_FILENO, ".", 1);
    putdec(pct % 10);

    write(STDOUT_FILENO, "%)\n", 3);
    /* Example: [+] Stripped: 16728 -> 12320 bytes (-26.3%) */



    /* Return success to stripped target file */
    return 0;
}
