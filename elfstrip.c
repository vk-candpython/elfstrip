//=================================\\
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 17
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 03.06.2026
//     PROJECT  : ELF-STRIPPER
//     PLATFORM : LINUX
//=================================\\




/* Enables GNU and Linux-specific extensions */
#define _GNU_SOURCE


#define ZERO       0    // Zero out data 
#define MIN_ELF_SZ 1024 // 1 KB: Min size for strip ELF 


/* Check for error sentinel */
#define IS_FAIL(e) ((e) == -1)   


/* Centralized error message string constants */
#define ERR_OS(nm)     "OSError: " #nm "() failed"
#define ERR_MIN_SZ     "file size is below minimum ELF threshold"
#define ERR_IS_ELF     "file is not valid ELF binary"
#define ERR_ELF_ST     "invalid ELF file structure"
#define ERR_ELF_TP     "unsupported ELF file type (only ET_EXEC and ET_DYN)"
#define ERR_ARCH(n)    "ELF file architecture is not " #n




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
#define PHDR_DEF(ph, src, is_x86) do {            \
    if (is_x86) (ph).x32 = (Elf32_Phdr*)(src);    \
    else        (ph).x64 = (Elf64_Phdr*)(src);    \
} while (0)


/* Safely initializes the architecture-agnostic executable header wrapper */
#define EHDR_DEF(eh, src, is_x86) do {            \
    if (is_x86) (eh).x32 = (Elf32_Ehdr*)(src);    \
    else        (eh).x64 = (Elf64_Ehdr*)(src);    \
} while (0)


/* Safely extracts a field from the architecture-agnostic header */
#define HD_GET(hd, is_x86, field) \
    ((is_x86)? (hd).x32->field : (hd).x64->field)


/* Safely updates a field in the architecture-agnostic header */
#define HD_SET(hd, is_x86, field, val) do {    \
    if (is_x86) (hd).x32->field = (val);       \
    else        (hd).x64->field = (val);       \
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
static inline void cerr(const char *s) {
    if (s) {
        write(STDERR_FILENO, s,    strlen(s));
        write(STDERR_FILENO, "\n", 1        );
    }
    _exit(1); // Terminate process immediately
}




int main(int argc, char *argv[]) {
    if (argc != 2) cerr(
        "\n(C) Vladislav Khudash, 2026."
        "\n(I) Extreme ELF-file metadata stripper."
        "\n(P) GitHub: https://github.com/vk-candpython/elfstrip"
        "\n(!) Warning: Modifies target file in-place."
        "\n\n(Usage): elfstrip <elf-file>\n"
    ); // Enforce correct CLI usage and display tool metadata
    


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

    fsz = st.st_size;
    if (fsz < MIN_ELF_SZ) cerr(ERR_MIN_SZ); }

    
    /* Map the target binary into the process address space 
       for direct mutation */
    void *map = mmap(NULL, fsz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, ZERO);
    if (map == MAP_FAILED) cerr(ERR_OS(mmap));


    
    /* Validate the ELF Magic number prefix */
    uint8_t *ident = (uint8_t*)map;

    if (memcmp(ident, ELFMAG, SELFMAG)) 
        cerr(ERR_IS_ELF);



    /* 
    Detect architecture class boundaries:
        is_x86 : 1 for 32-bit targets, 0 for 64-bit targets
        is_arm : Flag for ARM/AArch64 platform-specific handling
    */
    uint8_t is_x86 = ident[EI_CLASS] == ELFCLASS32,
            is_arm = 0;



    /* Phase 1: Validate ELF structures 
       and extract layout metadata */
    size_t     e_phoff,   e_phentsize, e_phnum;
    { uint16_t e_machine, e_type;


    Elf_Ehdr eh;
    EHDR_DEF(eh, map, is_x86);

    e_machine   = HD_GET(eh, is_x86, e_machine  ); // Target ISA architecture
    e_type      = HD_GET(eh, is_x86, e_type     ); // ELF binary type identifier
    e_phoff     = HD_GET(eh, is_x86, e_phoff    ); // Program headers table offset
    e_phentsize = HD_GET(eh, is_x86, e_phentsize); // Size of single program header
    e_phnum     = HD_GET(eh, is_x86, e_phnum    ); // Total count of program headers


    if (is_x86) { // Validate target as a 32-bit architecture ELF
        if (e_phentsize != sizeof(Elf32_Phdr)) 
            cerr(ERR_ELF_ST);

        if ((e_machine != EM_386) && (e_machine != EM_ARM)) 
            cerr(ERR_ARCH(x86));
    } 
    else { // Validate target as a 64-bit architecture ELF
        if (ident[EI_CLASS] != ELFCLASS64) 
            cerr(ERR_ARCH(x64));

        if (e_phentsize != sizeof(Elf64_Phdr)) 
            cerr(ERR_ELF_ST);

        if ((e_machine != EM_X86_64) && (e_machine != EM_AARCH64)) 
            cerr(ERR_ARCH(x64));
    }


    /* Identify ARM/AArch64 target ISA */
    is_arm = (e_machine == EM_ARM) || (e_machine == EM_AARCH64);



    /* Enforce execution-capable binary types */
    if ((e_type != ET_EXEC) && (e_type != ET_DYN))
        cerr(ERR_ELF_TP); }



    /* Prevent integer overflows 
       during layout boundaries computation */
    size_t   phe = 0; // Program header table end offset
    { size_t bph = 0; // Total size of PH table

    if (__builtin_mul_overflow(e_phnum, e_phentsize, &bph) || 
        __builtin_add_overflow(e_phoff, bph,         &phe) || 
        (phe > fsz)
    ) cerr(ERR_ELF_ST); }



    /* Allocate an internal tracking table 
       for protected memory regions */
    size_t rgcn = 1,                                // Initial protected region count (ELF header)
           rgsz = (e_phnum + 1) * sizeof(Region_t); // Buffer size for region tracking table


    Region_t *regs = (Region_t*)mmap(NULL, rgsz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, ZERO);
    if (regs == MAP_FAILED) cerr(ERR_OS(mmap));


    regs[0].start = 0;   // Anchor the base region at the absolute start of the file (ELF Header)
    regs[0].end   = phe; // Mark the entire Program Header Table boundary as protected


    
    /* Phase 2: Architecture-agnostic processing loop 
       via polymorphic macro layer */
    uint16_t aphnm = 0;                        // Active program headers counter
    size_t   dynsz = is_x86?
        sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn); // Dyn entry size

    { void *phbs  = PHDR_BASE(map, e_phoff);         // PH table base address
    for (uint16_t i = 0;  i < e_phnum;  ++i) {
        void *src = PHDR_ADDR(phbs, i, e_phentsize); // Current PH entry ptr


        Elf_Phdr ph;
        PHDR_DEF(ph, src, is_x86);

        uint32_t p_type   = HD_GET(ph, is_x86, p_type  ); // Program segment type identifier
        size_t   p_filesz = HD_GET(ph, is_x86, p_filesz), // Segment size within the file image
                 p_offset = HD_GET(ph, is_x86, p_offset); // Segment offset from start of file


        /* Safeguard against integer overflow 
           and out-of-bounds mapping */
        size_t sge = 0; // Calculate & validate segment end
        if (__builtin_add_overflow(p_offset, p_filesz, &sge) ||
            (sge > fsz)
        ) continue; 


        /* Precompute segment base address */
        void *segbs = PHDR_BASE(map, p_offset);



        /* Strip non-essential or empty metadata segments */
        switch (p_type) {
            case PT_NOTE         : // Auxiliary metadata and build notes
                memset(segbs, ZERO, p_filesz);
                continue;

            case PT_GNU_EH_FRAME : // GNU exception handling frame descriptor
            case PT_ARM_EXIDX    : // ARM exception unwind index table
                if (!p_filesz) continue; // Skip empty tracking tables safely
            
            default              : // Core executable segments handling
                break;
        }


        /* Anonymize trailing slack space in interpreter path */
        if (p_type == PT_INTERP) {
            char  *pt = (char*)segbs;              // Interpreter path base
            size_t ln = strnlen(pt, p_filesz) + 1; // Calc path length (incl. null)


            /* Zero out trailing bytes after 
               the null-terminated path string */
            if (ln < p_filesz) {
                memset(PHDR_BASE(pt, ln), ZERO, p_filesz - ln); // Clear slack


                HD_SET(ph, is_x86, p_filesz, ln); // Update file size
                HD_SET(ph, is_x86, p_memsz,  ln); // Update mem size

                p_filesz = ln;            // Sync local size
                sge      = p_offset + ln; // Refresh boundary
            }
        }


        /* Sanitize and compact the dynamic linking table */
        else if (p_type == PT_DYNAMIC) {
            char  *dptr = (char*)segbs; // Dynamic table base
            size_t wofs = 0;            // Compaction write offset


            for (
                size_t rofs = 0; // Dynamic table read offset
                (rofs + dynsz) <= p_filesz;  
                rofs += dynsz
            ) {
                void *s = PHDR_BASE(dptr, rofs); // Get current entry addr
                
                int64_t  tg  = is_x86? ((Elf32_Dyn*)s)->d_tag      : ((Elf64_Dyn*)s)->d_tag;      // Get dynamic tag
                uint64_t dvl = is_x86? ((Elf32_Dyn*)s)->d_un.d_val : ((Elf64_Dyn*)s)->d_un.d_val; // Get dynamic value


                /* Filter and sanitize dynamic table entries */
                switch (tg) {
                    case DT_DEBUG    : // Hook for runtime debuggers (e.g., GDB)
                    case DT_RPATH    : // Library search path (obsolete)
                    case DT_RUNPATH  : // Library search path (current)
                        continue; // Always drop compiler/linker debug footprints

                    case DT_NULL     : // End-of-table sentinel marker
                    case DT_TEXTREL  : // Read-only segments relocation indicator
                    case DT_BIND_NOW : // Non-lazy runtime binding directive
                        break; // Critical markers: must be preserved even if value is ZERO

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


            /* Truncate and finalize segment sizes after compaction */
            if (wofs < p_filesz) {
                /* Clear trailing space left by deleted dynamic entries */
                memset(PHDR_BASE(dptr, wofs), ZERO, p_filesz - wofs);


                HD_SET(ph, is_x86, p_filesz, wofs); // Update file size field in program header
                HD_SET(ph, is_x86, p_memsz,  wofs); // Update memory size field in program header

                p_filesz = wofs;            // Sync local size
                sge      = p_offset + wofs; // Recalculate exact segment upper boundary offset
            }
        }

        

        /* Filter, pack, and record critical 
           program headers for preservation */
        if (is_crit_seg(p_type)) {
            /* Calculate the absolute memory address 
               of the target program header entry */
            void *dst = PHDR_ADDR(phbs, aphnm, e_phentsize);

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


        Elf_Phdr phz;
        PHDR_DEF(phz, dst, is_x86);
        
        /* Update PT_PHDR entry to match compacted size */
        if (HD_GET(phz, is_x86, p_type) == PT_PHDR) {
            size_t nwsz = aphnm * e_phentsize; // Compacted PH table size


            HD_SET(phz, is_x86, p_filesz, nwsz   ); // Update file size
            HD_SET(phz, is_x86, p_memsz,  nwsz   ); // Update mem size
            HD_SET(phz, is_x86, p_offset, e_phoff); // Update segment offset 
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
        pos = regs[i].end;
    } }



    /* Phase 5: Destructively wipe Section Headers reference 
       and update the ELF Header via unified macro layer */
    { Elf_Ehdr ehf;
    EHDR_DEF(ehf, map, is_x86);

    HD_SET(ehf, is_x86, e_phnum,     aphnm); // Update to active program headers count
    HD_SET(ehf, is_x86, e_shnum,     ZERO ); // Clear total section headers counter
    HD_SET(ehf, is_x86, e_shoff,     ZERO ); // Wipe section header table file offset
    HD_SET(ehf, is_x86, e_shentsize, ZERO ); // Zero out section header entry size
    HD_SET(ehf, is_x86, e_shstrndx,  ZERO ); // Drop section name string table index
    
    if (!is_arm)
        HD_SET(ehf, is_x86, e_flags, ZERO ); // Reset target platform processor flags
    }


    /* Anonymize standard padding bytes within e_ident */
    memset(&ident[EI_OSABI], ZERO, EI_NIDENT - EI_OSABI);



    /* Phase 6: Commit modified pages to storage 
       and perform aggressive physical truncation */

    /* Calculate truncated size based 
       on last active region */
    size_t nwfsz = regs[mrcn - 1].end; 


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

    
    
    close(fd); // Close target file descriptor
    return  0; // Return success to the operating system
}
