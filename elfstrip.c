//=================================\\
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 17
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 01.06.2026
//     PROJECT  : ELF-STRIPER
//     PLATFORM : LINUX
//=================================\\




#define _GNU_SOURCE
#define ZERO 0           // Zero out data 
#define MIN_ELF_SZ 1024  // 1 KB: Min size for strip ELF 




#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <err.h>


#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>




/* Represents a protected memory segment boundary */
typedef struct {  size_t start, end;  } Region;


/* Architecture-agnostic wrapper for ELF Program Headers */
typedef union {
    Elf32_Phdr *x32; // Ptr to 32-bit header 
    Elf64_Phdr *x64; // Ptr to 64-bit header 
} Elf_Phdr;

/* Architecture-agnostic wrapper for ELF Executable Headers */
typedef union {
    Elf32_Ehdr *x32; // Ptr to 32-bit executable header
    Elf64_Ehdr *x64; // Ptr to 64-bit executable header
} Elf_Ehdr;



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
        case PT_LOAD         : // Code and Data segments
        case PT_DYNAMIC      : // Dynamic linking information
        case PT_INTERP       : // Path to the dynamic linker
        case PT_PHDR         : // Program header table 
        case PT_TLS          : // Thread-Local Storage architecture
        case PT_GNU_RELRO    : // Read-only after relocation
        case PT_GNU_STACK    : // Stack execution control (NX bit)
        case PT_GNU_EH_FRAME : // Exception unwinding frame
        case PT_ARM_EXIDX    : // ARM exception unwind tables
        case PT_GNU_PROPERTY : // Hardware property controls (Intel CET / IBT / SHSTK)
            return 1;
        default              : // Non-critical segment (eligible for removal)
            return 0;         
    }
}




/* In-place insertion sort to order tracked regions 
   by their starting offsets */
static inline void sort_regs(Region *arr, size_t sz) {
    Region *end = arr + sz;

    for (Region *p = arr + 1;  p < end;  ++p) {
        Region k = *p,
              *q = p;

        while ((q > arr) && ((q - 1)->start > k.start)) {
            *q = *(q - 1); --q;
        }
        *q = k;
    }
}




int main(int argc, char *argv[]) {
    if (argc != 2) {
        const char *nm = strrchr(argv[0], '/');
        nm             = nm? nm + 1 : argv[0];

        errx(1, "\n\t(C) Vladislav Khudash, 2026"
                "\n\t(P) GitHub: https://github.com/vk-candpython/elfstrip"
                "\n\n\t(Usage): %s <elf-file>", nm);
    }



    /* Phase 0: File initialization, validation, 
       and memory mapping for direct binary manipulation */
    int fd = open(argv[1], O_RDWR);
    if (fd == -1) err(1, "open");
    size_t fsz;

    /* Retrieve target file metadata 
       and perform basic size validation */
    { struct stat st;
    if (fstat(fd, &st) == -1) err(1, "fstat");

    fsz = st.st_size;
    if (fsz < MIN_ELF_SZ) errx(1, "file is small for striping ELF"); }

    
    /* Map the target binary into the process address space 
       for direct mutation */
    void *map = mmap(NULL, fsz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) err(1, "mmap");


    
    /* Validate the ELF Magic number prefix */
    uint8_t *ident = (uint8_t*)map;
    if (memcmp(ident, ELFMAG, SELFMAG)) errx(1, "file is not ELF");



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


    if (is_x86) {
        if (e_phentsize != sizeof(Elf32_Phdr)) 
            errx(1, "invalid ELF file");

        if ((e_machine != EM_386) && (e_machine != EM_ARM)) 
            errx(1, "ELF is not x86");
    } 
    else {
        if (ident[EI_CLASS] != ELFCLASS64) 
            errx(1, "ELF is not x64");

        if (e_phentsize != sizeof(Elf64_Phdr)) 
            errx(1, "invalid ELF file");

        if ((e_machine != EM_X86_64) && (e_machine != EM_AARCH64)) 
            errx(1, "ELF is not x64");
    }
    is_arm = (e_machine == EM_ARM) || (e_machine == EM_AARCH64);



    /* Enforce execution-capable binary types */
    if ((e_type != ET_EXEC) && (e_type != ET_DYN))
        errx(1, "unsupported ELF type (only ET_EXEC and ET_DYN)"); }



    /* Prevent integer overflows 
       during layout boundaries computation */
    size_t   phe;
    { size_t bph;
    if (__builtin_mul_overflow(e_phnum, e_phentsize, &bph) || 
        __builtin_add_overflow(e_phoff, bph,         &phe) || 
        (phe > fsz)
    ) errx(1, "invalid ELF file"); }



    /* Allocate an internal tracking table 
       for protected memory regions */
    size_t rgcn = 1,
           rgsz = (1 + e_phnum) * sizeof(Region);

    Region *regs = (Region*)mmap(NULL, rgsz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (regs == MAP_FAILED) err(1, "mmap anonymous failed");

    regs->start = 0;
    regs->end   = phe;


    
    /* Phase 2: Architecture-agnostic processing loop 
       via polymorphic macro layer */
    uint16_t aphnm = 0;

    { char *phbs = (char*)map + e_phoff;
    for (uint16_t i = 0;  i < e_phnum;  ++i) {
        void *src = phbs + i * e_phentsize;


        Elf_Phdr ph;
        PHDR_DEF(ph, src, is_x86);

        uint32_t p_type   = HD_GET(ph, is_x86, p_type  ); // Program segment type identifier
        size_t   p_filesz = HD_GET(ph, is_x86, p_filesz), // Segment size within the file image
                 p_offset = HD_GET(ph, is_x86, p_offset); // Segment offset from start of file


        /* Safeguard against integer overflow 
           and out-of-bounds mapping */
        size_t sge;
        if (__builtin_add_overflow(p_offset, p_filesz, &sge) || (sge > fsz)) 
            continue; 



        /* Strip non-essential or empty metadata segments */
        switch (p_type) {
            case PT_NOTE         : // Auxiliary metadata and build notes
                memset((char*)map + p_offset, ZERO, p_filesz);
                continue;
            case PT_GNU_EH_FRAME : // GNU exception handling frame descriptor
            case PT_ARM_EXIDX    : // ARM exception unwind index table
                if (!p_filesz) continue; // Skip empty tracking tables safely
            default              : // Core executable segments handling
                break;
        }


        /* Anonymize trailing slack space in interpreter path */
        if (p_type == PT_INTERP) {
            char  *pt = (char*)map + p_offset;
            size_t ln = strnlen(pt, p_filesz);

            if (ln < p_filesz) memset(pt + ln, ZERO, p_filesz - ln); // Zero out trailing bytes after the null-terminated path string
        }


        /* Sanitize and compact the dynamic linking table */
        if (p_type == PT_DYNAMIC) {
            size_t dsz  = is_x86? 
                sizeof(Elf32_Dyn): 
                sizeof(Elf64_Dyn);
            char  *dptr = (char*)map + p_offset;
            size_t wofs = 0;


            for (
                size_t rofs = 0;  
                (rofs + dsz) <= p_filesz;  
                rofs += dsz
            ) {
                void   *s   = dptr + rofs;
                int64_t tg  = is_x86? 
                    ((Elf32_Dyn*)s)->d_tag: 
                    ((Elf64_Dyn*)s)->d_tag;
                size_t  dvl = is_x86? 
                    ((Elf32_Dyn*)s)->d_un.d_val: 
                    ((Elf64_Dyn*)s)->d_un.d_val;


                /* Filter out optional or debugging dynamic entries */
                switch (tg) {
                    case DT_DEBUG      : // Drop debugger pointer
                        continue;
                    case DT_VERNEED    : // GNU Version requirements
                    case DT_VERNEEDNUM : // GNU Version count
                    case DT_VERDEF     : // GNU Version definitions
                    case DT_VERDEFNUM  : // GNU Version def count
                    case DT_VERSYM     : // GNU Version symbol table
                    case DT_RPATH      : // Run-time search path 
                    case DT_RUNPATH    : // New-style run-time search path 
                        if (!dvl) continue; // Delete if empty
                    default            : // Preserve all core tags
                        break;
                }


                void *d = dptr + wofs;
                if (s != d) memmove(d, s, dsz); // Shift valid dynamic entry forward to eliminate gaps
                wofs += dsz;
                
                
                /* Terminate processing upon reaching the end-of-table marker */
                if (tg == DT_NULL) {
                    if (is_x86) ((Elf32_Dyn*)d)->d_un.d_val = ZERO;
                    else        ((Elf64_Dyn*)d)->d_un.d_val = ZERO;
                    break;
                }
            }


            /* Truncate and finalize segment sizes after compaction */
            if (wofs < p_filesz) {
                memset(dptr + wofs, ZERO, p_filesz - wofs); // Clear trailing space left by deleted dynamic entries

                HD_SET(ph, is_x86, p_filesz, wofs); // Update file size field in program header
                HD_SET(ph, is_x86, p_memsz,  wofs); // Update memory size field in program header

                p_filesz = wofs;
                sge      = p_offset + wofs; // Recalculate exact segment upper boundary offset
            }
        }

        

        /* Filter, pack, and record critical program headers for preservation */
        if (p_filesz && is_crit_seg(p_type)) {
            void *dst = phbs + aphnm * e_phentsize;
            if (src != dst) memmove(dst, src, e_phentsize); // Pack valid header entry to eliminate holes

            
            Elf_Phdr phz;
            PHDR_DEF(phz, dst, is_x86);
            HD_SET(phz, is_x86, p_paddr, ZERO); // Zero out physical address for segment

            if (p_type != PT_LOAD) HD_SET(phz, is_x86, p_align, ZERO); // Zero out alignment constraints for non-loadable segments
            

            regs[rgcn].start = p_offset; // Save protected interval starting point
            regs[rgcn].end   = sge;      // Save protected interval ending point
            rgcn++; aphnm++;             // Advance region tracker and active headers counter
        }
    } }



    /* Zero out the slack space left behind 
       by omitted program headers */
    if (aphnm < e_phnum) {
        size_t ddst =  e_phoff + (aphnm * e_phentsize),
               ddln = (e_phnum - aphnm) * e_phentsize;

        memset((char*)map + ddst, ZERO, ddln);
    }



    /* Sort tracked memory regions sequentially 
       by their starting offsets 
       to prepare for the interval merging phase */
    sort_regs(regs, rgcn);



    /* Phase 3: Merge overlapping 
       or adjacent protected memory regions */
    size_t mrcn = 0;
    for (size_t i = 1;  i < rgcn;  ++i) {
        if (regs[i].start > regs[mrcn].end) 
            regs[++mrcn]  = regs[i];        // Non-contiguous region detected, push next

        else if (regs[i].end > regs[mrcn].end) 
            regs[mrcn].end   = regs[i].end; // Overlap found, expand current upper bound
    } mrcn++; // Fix count of collapsed active regions



    /* Phase 4: Wipe out all unmapped gaps 
       (sections, debug symbols, strings tables) */
    { size_t pos = regs->end;
    for (size_t i = 1;  i < mrcn;  ++i) {
        if (regs[i].start > pos) 
            memset((char*)map + pos, ZERO, regs[i].start - pos);

        pos = regs[i].end; // Advance reference pointer to segment end
    } }



    /* Fill the remaining trailing 
       file data with zeroes */
    size_t nwfsz = regs[mrcn - 1].end;
    if (nwfsz < fsz) memset((char*)map + nwfsz, ZERO, fsz - nwfsz);
    


    /* Phase 5: Destructively wipe Section Headers reference 
       and update the ELF Header via unified macro layer */
    { Elf_Ehdr ehf;
    EHDR_DEF(ehf, map, is_x86);

    HD_SET(ehf, is_x86, e_phnum,     aphnm); // Update to active program headers count
    HD_SET(ehf, is_x86, e_ehsize,    ZERO ); // Wipe internal ELF header size descriptor
    HD_SET(ehf, is_x86, e_shnum,     ZERO ); // Clear total section headers counter
    HD_SET(ehf, is_x86, e_shoff,     ZERO ); // Wipe section header table file offset
    HD_SET(ehf, is_x86, e_shentsize, ZERO ); // Zero out section header entry size
    HD_SET(ehf, is_x86, e_shstrndx,  ZERO ); // Drop section name string table index
    
    if (!is_arm)
        HD_SET(ehf, is_x86, e_flags, ZERO ); // Reset target platform processor flags
    }



    /* Anonymize standard padding bytes within e_ident */
    for (uint8_t i = EI_OSABI;  i < EI_NIDENT;  ++i)
        ident[i] = ZERO;



    /* Phase 6: Commit modified pages to storage 
       and perform aggressive physical truncation */
    if (msync(map, fsz, MS_SYNC) == -1) err(1, "msync");
    munmap(map, fsz);
    if (ftruncate(fd, nwfsz)     == -1) err(1, "ftruncate");
    

    close(fd);
    munmap(regs, rgsz);
    return 0;
}
