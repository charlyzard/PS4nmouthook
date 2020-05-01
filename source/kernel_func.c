#include "kernel_func.h"

void kern_process_readwrite_mem(struct proc* p, uint64_t offset, void* data, uint64_t size, int is_write) {
	uint8_t* ptrKernel = (uint8_t *)(readMsr(0xC0000082) - KERN_XFAST_SYSCALL);

	int (*proc_rwmem)(struct proc *p, struct uio *uio) = (void *)&ptrKernel[KERN_PROC_RWMEM];
	int (*printfkernel)(const char *fmt, ...) = (void *)&ptrKernel[KERN_PRINTF];

	struct uio uio;
	struct iovec iov;
	iov.iov_base = data;
	iov.iov_len = size;

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = offset;
	uio.uio_resid = size;
	uio.uio_segflg = UIO_SYSSPACE;
	if (!is_write) {
		uio.uio_rw = UIO_READ;
	} else {
		uio.uio_rw = UIO_WRITE;
	}
	uio.uio_td = curthread();

	proc_rwmem(p, &uio);
}

Map* kern_process_vm_map(struct proc* p, int* map_nbr) {
	struct vm_map_entry *entry;
	int error = 0;

	uint8_t* ptrKernel = (uint8_t *)(readMsr(0xC0000082) - KERN_XFAST_SYSCALL);

	void *M_TEMP = (void *)&ptrKernel[KERN_M_TEMP];
	void* (*k_malloc)(unsigned long size, void *type, int flags) = (void *)&ptrKernel[KERN_MALLOC];
	void (*k_free)(void *addr, void *type) = (void *)&ptrKernel[KERN_FREE];
	void (*k_memcpy)(void *dst, const void *src, size_t len) = (void*)&ptrKernel[KERN_MEMCPY];
	struct vmspace *(*vmspace_acquire_ref)(struct proc *p) = (void *)&ptrKernel[KERN_VMSPACE_ACQUIRE_REF];
	int (*vm_map_lookup_entry)(struct vm_map *map, uint64_t address, struct vm_map_entry **entries) = (void *)&ptrKernel[KERN_VM_MAP_LOOKUP_ENTRY];
	void (*vmspace_free)(struct vmspace *vm) = (void *)&ptrKernel[KERN_VMSPACE_FREE];
	void (*vm_map_lock_read)(struct vm_map *map) = (void *)&ptrKernel[KERN_VM_MAP_LOCK_READ];
	void (*vm_map_unlock_read)(struct vm_map *map) = (void *)&ptrKernel[KERN_VM_MAP_UNLOCK_READ];
	int (*printfkernel)(const char *fmt, ...) = (void *)&ptrKernel[KERN_PRINTF];

	struct vmspace *vm = vmspace_acquire_ref(p);
	if (!vm) {
		return 0;
	}

	struct vm_map *map = &vm->vm_map;

	int num = map->nentries;
	if (!num) {
		vmspace_free(vm);
		return 0;
	}

	vm_map_lock_read(map);
	if (vm_map_lookup_entry(map, NULL, &entry)) {
		*map_nbr = num;
		vm_map_unlock_read(map);
		vmspace_free(vm);
		return 0;
	}

	Map* map_list = k_malloc(sizeof(Map)*num, M_TEMP, 2);

	for (int i = 0; i < num; i++) {
		int prot = entry->prot & (entry->prot >> 8);

		uint64_t start = (uint64_t)entry->start;
		uint64_t stop = (uint64_t)entry->end;

		map_list[i].start = start;
		map_list[i].stop = stop;
		map_list[i].protection = prot;
		k_memcpy(map_list[i].name, entry->name, 32);

		if (!(entry = entry->next)) {
			break;
		}
	}
	
	*map_nbr = num;
	vm_map_unlock_read(map);
	vmspace_free(vm);

	return map_list;
}

struct proc * proc_find_by_name(char* name) {
	struct proc *p;

	uint8_t* ptrKernel = (uint8_t *)(readMsr(0xC0000082) - KERN_XFAST_SYSCALL);
	int (*k_strcmp)(const char *s1, const char *s2) = (void *)&ptrKernel[KERN_STRCMP];
	p = *(struct proc **)&ptrKernel[KERN_ALLPROC];

	do {
		if ( k_strcmp(p->p_comm, name) == 0 ) {
			return p;
		}
	} while ((p = p->p_forw));

	return NULL;
}

int sys_nmount_hook(struct thread* td, struct syscall_nmount* args) {

	uint8_t* ptrKernel = (uint8_t *)(readMsr(0xC0000082) - KERN_XFAST_SYSCALL);
	struct nmount_hook_data* data = (struct nmount_hook_data*)( *(uint64_t*)ptrKernel );

	struct ucred* cred = td->td_proc->p_ucred;

	int (*printfkernel)(const char *fmt, ...) = (void *)&ptrKernel[KERN_PRINTF];
	char* (*k_strncmp)(char * dst, const char * src, size_t len) = (void *)&ptrKernel[KERN_STRNCMP];
	char* (*k_strcpy)(char * dst, const char * src) = (void *)&ptrKernel[KERN_STRCPY];
	void* (*k_memcpy)(void *restrict dst, const void *restrict src, size_t n) = (void *)&ptrKernel[KERN_MEMCPY];
	size_t (*k_strlen)(const char *s) = (void *)&ptrKernel[KERN_STRLEN];
	int (*original_call)(struct thread* td, void* args) = (void *)&ptrKernel[KERN_SYS_NMOUNT];

	int ret = -1;
	
	printfkernel(data->print_debug1, args->niov);

	ret = original_call(td, args);
	
	
	
	int cuantos = args->niov;
	
	for (int i = 0 ; i < cuantos; i++) {
		printfkernel(data->print_debug3, args->iov[i].iov_base);
	}
	
	printfkernel(data->print_debug2, ret);

	return ret;

}

void* rwx_kalloc(int size) {
	uint8_t* ptrKernel = (uint8_t *)(readMsr(0xC0000082) - KERN_XFAST_SYSCALL);
	
	int fsize = (size + 0x3FFFull) & ~0x3FFFull;

	vm_offset_t (*kmem_alloc)(vm_map_t map, vm_size_t size) = (void *)&ptrKernel[KERN_KMEM_ALLOC];
	vm_map_t kernel_map = *(vm_map_t *)(void *)&ptrKernel[KERN_KERNEL_MAP];

	return (void*)kmem_alloc(kernel_map, fsize);
}

void install_nmount_hooks(void) {
	uint8_t* ptrKernel = (uint8_t *)(readMsr(0xC0000082) - KERN_XFAST_SYSCALL);
	void *M_TEMP = (void *)&ptrKernel[KERN_M_TEMP];
	void* (*k_memcpy)(void *restrict dst, const void *restrict src, size_t n) = (void *)&ptrKernel[KERN_MEMCPY];
	char* (*k_strcpy)(char * dst, const char * src) = (void *)&ptrKernel[KERN_STRCPY];
	int (*printfkernel)(const char *fmt, ...) = (void *)&ptrKernel[KERN_PRINTF];
	void (*k_free)(void *addr, void *type) = (void *)&ptrKernel[KERN_FREE];
	struct sysent* sysents = (void *)&ptrKernel[KERN_SYSENTS];

	struct nmount_hook_data* data = (struct nmount_hook_data*)rwx_kalloc(sizeof(struct nmount_hook_data));
	
	k_strcpy(data->print_debug1, "------------------------------------ Before original nmount -- %d\n");
	k_strcpy(data->print_debug2, "------------------------------------ After original nmount -- returns -- %d\n");
	k_strcpy(data->print_debug3, "------------------------------------------- %s\n");

	data->sys_nmount_orig = sysents[378].sy_call;

	void* hook_ptr = (void*)rwx_kalloc(0x10000);
	k_memcpy(hook_ptr, sys_nmount_hook, sizeof(sys_nmount_hook));
	
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	*(uint64_t*)ptrKernel = data;
	sysents[378].sy_call = hook_ptr;

	writeCr0(cr0);

}

int jailbreak(struct thread *td) {
	uint8_t* ptrKernel = (uint8_t *)(readMsr(0xC0000082) - KERN_XFAST_SYSCALL);
	struct ucred* cred = td->td_proc->p_ucred;
	struct filedesc* fd = td->td_proc->p_fd;

	// Escalate privileges
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	// Escape sandbox
	void** prison0 = (void**)&ptrKernel[KERN_PRISON_0];
	void** rootvnode = (void**)&ptrKernel[KERN_ROOTVNODE];
	cred->cr_prison = *prison0;
	fd->fd_rdir = fd->fd_jdir = *rootvnode;

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred

	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xFFFFFFFFFFFFFFFFULL;

	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access

	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xFFFFFFFFFFFFFFFFULL; // Sce Process

	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// Process ASLR Bypass
	*(uint16_t *)&ptrKernel[KERN_PROCESS_ASLR] = 0x9090;

	// Allow RWX with kmem_alloc
	*(uint8_t *)(ptrKernel + 0xFCD48) = 7; // VM_PROT_ALL;
	*(uint8_t *)(ptrKernel + 0xFCD56) = 7; // VM_PROT_ALL;

	// Enable write protection
	writeCr0(cr0);

	// Install all needed part
	install_nmount_hooks();

	return 0;
}
