#include "ps4.h"
#include "sparse.h"
#include "kernel_func.h"

int _main(struct thread *td) {
	// Init and resolve needed libraries
	initKernel();
	initLibc();

	syscall(11, jailbreak);
	return 0;
}