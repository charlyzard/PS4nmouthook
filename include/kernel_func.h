#include "ps4.h"
#include "sparse.h"
#include "freebsd.h"

typedef uintptr_t vm_offset_t;
typedef void* vm_map_t;
typedef char *caddr_t;

// 505
#define	KERN_XFAST_SYSCALL 0x1C0
#define KERN_PROCESS_ASLR 0x194875
#define KERN_PRISON_0 0x10986A0
#define KERN_ROOTVNODE 0x22C1A70
#define KERN_PRIV_CHECK 0x14A3990
#define KERN_PRIV_CHECK_CRED 0x2300B88
#define KERN_ALLOW_SYSTEM_LEVEL_DEBUGGING 0x1173D
#define KERN_COPYOUT 0x1EA630
#define KERN_COPYIN 0x1EA710
#define KERN_ALLPROC 0x2382FF8
#define KERN_PRINTF 0x436040
#define KERN_PROC_RWMEM 0x30D150
#define KERN_CREATE_THREAD 0x1BE1F0
#define KERN_KILLPROC 0xD41C0

#define	KERN_KMEM_ALLOC 0xFCC80
#define	KERN_KMEM_FREE 0xFCE50
#define KERN_KERNEL_MAP 0x1AC60E0

#define KERN_VMSPACE_ACQUIRE_REF 0x19EF90
#define KERN_VM_MAP_LOCK_READ 0x19f140
#define KERN_VM_MAP_UNLOCK_READ 0x19f190
#define	KERN_VMSPACE_ALLOC 0x19eb20
#define	KERN_VMSPACE_FREE 0x19edc0
#define KERN_VM_MAP_LOOKUP_ENTRY 0x19F760
#define KERN_VM_MAP_FINDSPACE 0x1A1F60
#define KERN_VM_MAP_INSERT 0x1A0280
#define KERN_VM_MAP_UNLOCK 0x19F060
#define KERN_VM_MAP_LOCK 0x19EFF0
#define KERN_VM_MAP_DELETE 0x1A19D0

#define KERN_M_TEMP 0x14B4110
#define KERN_FREE 0x10E460
#define KERN_MALLOC 0x10E250
#define KERN_STRCPY 0x8F250
#define KERN_STRCMP 0x1D0FD0
#define KERN_STRNCMP 0x1B8FE0
#define KERN_STRLEN 0x3B71A0
#define KERN_MEMCPY 0x1EA530
#define KERN_MEMSET 0x3205C0


#define KERN_SYS_MMAP 0x13D230
#define KERN_SYS_OPEN 0x33B990
#define KERN_SYS_NMOUNT 0x1DE2E0
#define KERN_SYS_DYNLIB_LOAD_PRX 0x237930

#define KERN_SYSENTS 0x107C610

#define X86_CR0_WP (1 << 16)

typedef struct {
	char name[32];
	uint64_t start;
	uint64_t stop;
	int protection;
} Map;

struct kern_uap {
	uint64_t syscall;
	void* uap;
};

struct open_hook_data {
	void* sys_open_orig;
	char data_path[100];
	char cusa[5];
	char print_debug1[100];
	char print_debug2[100];
};

struct nmount_hook_data {
	void* sys_nmount_orig;
	char print_debug1[100];
	char print_debug2[100];
	char print_debug3[100];
};

struct syscall_open {
	const char *path;
	int flags;
	int mode;
}  __attribute__((packed));

struct syscall_nmount {
	struct iovec *iov;
	unsigned int niov;
	int flags
}  __attribute__((packed));

static inline __attribute__((always_inline)) uint64_t readMsr(uint32_t __register) {
	uint32_t __edx, __eax;

	__asm__ volatile (
	    "rdmsr"
	    : "=d"(__edx),
	    "=a"(__eax)
	    : "c"(__register)
	);

	return (((uint64_t)__edx) << 32) | (uint64_t)__eax;
}

static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	__asm__ __volatile__ (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	__asm__ __volatile__ (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}

uint8_t* get_kptr();
int jailbreak(struct thread *td);
