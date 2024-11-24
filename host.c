#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/kvm.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <getopt.h>
#include <pty.h>
#include <semaphore.h>

// Define constants for file operations
#define OPEN 1
#define CLOSE 2
#define READ 3
#define WRITE 4
#define FINISH 0

// Define bitmasks for page directory and table entries
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_PS (1U << 7)

#define CR4_PAE (1U << 5)

#define CR0_PE 1u
#define CR0_PG (1U << 31)

#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)

#define SIZE2MB (2 * 1024 * 1024)

// Enum for page size (2MB or 4KB)
enum PageSize {MB2, KB4};

// Structure representing a hypervisor, containing the KVM file descriptor and the KVM run mmap size
struct hypervisor {
    int kvm_fd; // File descriptor for /dev/kvm
    int kvm_run_mmap_size; // Size of the memory map for the KVM run structure
};

/**
 * Initializes the hypervisor by opening the /dev/kvm file and getting the KVM run mmap size.
 *
 * @param hypervisor Pointer to the hypervisor structure.
 * @return 0 on success, -1 on failure.
 */
int init_hypervisor(struct hypervisor* hypervisor) {
    // Open the /dev/kvm file
    hypervisor->kvm_fd = open("/dev/kvm", O_RDWR);
    if (hypervisor->kvm_fd < 0) {
        // Print an error message if the file cannot be opened
        perror("ERROR: Unable to open /dev/kvm file\n");
        return -1;
    }

    // Get the size of the memory map for the KVM run structure
    hypervisor->kvm_run_mmap_size = ioctl(hypervisor->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (hypervisor->kvm_run_mmap_size < 0) {
        // Print an error message if the ioctl call fails
        perror("ERROR: Failed ioctl KVM_GET_VCPU_MMAP_SIZE\n");
        fprintf(stderr, "KVM_GET_VPCU_MMAP_SIZE: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

// Structure representing a file used by the guest VM
struct file {
    int fd; // File descriptor
    int flags; // Flags for opening the file
    mode_t mode; // Mode for opening the file
    int cnt; // Counter for the file name length
    struct file* next; // Pointer to the next file in the list
    char ime[50]; // File name
};

// Structure representing a guest VM
struct guest {
    int vm_fd; // File descriptor for the VM
    int vm_vcpu; // File descriptor for the virtual CPU
    int pty_master; // File descriptor for the master side of the pseudoterminal
    int pty_slave; // File descriptor for the slave side of the pseudoterminal
    int lock; // Lock for synchronizing file operations
    int id; // ID of the guest VM
    char* mem; // Pointer to the memory allocated for the guest
    struct kvm_run* kvm_run; // Pointer to the KVM run structure
    struct file* file_head; // Head of the file list
    struct file** file_indirect; // Indirect pointer to the file list
    struct file* current_file; // Pointer to the current file
};

/**
 * Creates a guest VM by issuing an ioctl call to KVM_CREATE_VM.
 *
 * @param hypervisor Pointer to the hypervisor structure.
 * @param vm Pointer to the guest structure.
 * @return 0 on success, -1 on failure.
 */
int create_guest(struct hypervisor* hypervisor, struct guest* vm) {
    // Create a VM by issuing an ioctl call to KVM_CREATE_VM
    vm->vm_fd = ioctl(hypervisor->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        // Print an error message if the VM creation fails
        perror("ERROR: Failed to create KVM VM\n");
        fprintf(stderr, "KVM_CREATE_VM: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Allocates memory for the guest VM and sets up the user memory region by issuing an ioctl call to KVM_SET_USER_MEMORY_REGION.
 *
 * @param vm Pointer to the guest structure.
 * @param mem_size Size of the memory to be allocated.
 * @return 0 on success, -1 on failure.
 */
int create_memory_region(struct guest* vm, size_t mem_size) {
    struct kvm_userspace_memory_region region;

    // Allocate memory for the guest VM
    vm->mem = (char*)mmap(NULL, mem_size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (vm->mem == MAP_FAILED) {
        // Print an error message if memory allocation fails
        perror("ERROR: Failed to mmap memory for guest\n");
        return -1;
    }

    // Set up the memory region structure
    region.slot = 0;
    region.flags = 0;
    region.guest_phys_addr = 0;
    region.memory_size = mem_size;
    region.userspace_addr = (unsigned long)vm->mem;

    // Set the user memory region for the guest VM
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        // Print an error message if the ioctl call fails
        perror("ERROR: Failed ioctl KVM_SET_USER_MEMORY_REGION\n");
        fprintf(stderr, "KVM_SET_USER_MEMORY_REGION: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Creates a virtual CPU (vCPU) for the guest VM by issuing an ioctl call to KVM_CREATE_VCPU.
 *
 * @param vm Pointer to the guest structure.
 * @return 0 on success, -1 on failure.
 */
int create_vcpu(struct guest* vm) {
    // Create a virtual CPU by issuing an ioctl call to KVM_CREATE_VCPU
    vm->vm_vcpu = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vm_vcpu < 0) {
        // Print an error message if the virtual CPU creation fails
        perror("ERROR: Failed ioctl KVM_CREATE_VCPU\n");
        fprintf(stderr, "KVM_CREATE_VCPU: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Maps the KVM run structure into the process's address space by issuing an mmap call.
 *
 * @param hypervisor Pointer to the hypervisor structure.
 * @param vm Pointer to the guest structure.
 * @return 0 on success, -1 on failure.
 */
int create_kvm_run(struct hypervisor* hypervisor, struct guest* vm) {
    // Map the KVM run structure into the process's address space
    vm->kvm_run = mmap(NULL, hypervisor->kvm_run_mmap_size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED, vm->vm_vcpu, 0);
    if (vm->kvm_run == MAP_FAILED) {
        // Print an error message if the mmap call fails
        perror("ERROR: Failed to mmap KVM run structure\n");
        return -1;
    }

    return 0;
}

/**
 * Sets up a 64-bit code segment for the guest VM by configuring the segment descriptor.
 *
 * @param sregs Pointer to the special registers structure.
 */
void setup_64bit_code_segment(struct kvm_sregs* sregs) {
    struct kvm_segment segment = {
        .base = 0,
        .limit = 0xffffffff,
        .present = 1,
        .type = 11, // Execute/Read, accessed
        .dpl = 0,
        .db = 0,
        .s = 1,
        .l = 1, // 64-bit code segment
        .g = 1
    };

    // Set the code segment
    sregs->cs = segment;
    segment.type = 3; // Read/Write, accessed
    // Set the data segments
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = segment;
}

/**
 * Sets up long mode for the guest VM by configuring the paging structures and special registers.
 *
 * @param vm Pointer to the guest structure.
 * @param mem_size Size of the memory allocated for the guest.
 * @param page_size Page size (2MB or 4KB).
 * @return Address of the first page on success, -1 on failure.
 */
int setup_long_mode(struct guest* vm, size_t mem_size, enum PageSize page_size) {
    struct kvm_sregs sregs;

    // Get the special registers of the virtual CPU
    if (ioctl(vm->vm_vcpu, KVM_GET_SREGS, &sregs) < 0) {
        // Print an error message if the ioctl call fails
        perror("ERROR: Failed ioctl KVM_GET_SREGS\n");
        fprintf(stderr, "KVM_GET_SREGS: %s\n", strerror(errno));
        return -1;
    }

    uint64_t pml4_addr = 0; // Address of the PML4
    uint64_t* pml4 = (void*)(vm->mem + pml4_addr); // Pointer to the PML4

    uint64_t pdpt_addr = 0x1000; // Address of the PDPT
    uint64_t* pdpt = (void*)(vm->mem + pdpt_addr); // Pointer to the PDPT

    uint64_t pd_addr = 0x2000; // Address of the page directory
    uint64_t* pd = (void*)(vm->mem + pd_addr); // Pointer to the page directory

    uint64_t page = 0x3000; // Initial page address

    // Set up the PML4 entry
    pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
    // Set up the PDPT entry
    pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

    if (page_size == MB2) {
        // Align the page address to 2MB
        page = (page / SIZE2MB + 1) * SIZE2MB;
        uint64_t page_address = page;
        for (int i = 0; i < mem_size / SIZE2MB - 1; i++) {
            // Set up the page directory entry for 2MB pages
            pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS | page_address;
            page_address += SIZE2MB;
        }
    } else {
        // Set up the page directory entry for 4KB pages
        for (int i = 0; i < mem_size / SIZE2MB; i++) {
            pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | page;
            page += 0x1000;
        }

        uint64_t page_address = page;
        for (int i = 0; i < mem_size / SIZE2MB; i++) {
            uint64_t pt_addr = pd[i] & ~0xFFFUL; // Address of the page table
            uint64_t* pt = (void*)vm->mem + pt_addr; // Pointer to the page table

            for (int j = 0; j < 512; j++) {
                if (page_address > mem_size) break;
                // Set up the page table entry
                pt[j] = page_address | PDE64_PRESENT | PDE64_RW | PDE64_USER;
                page_address += 0x1000;
            }
        }
    }

    // Set the special registers
    sregs.cr3 = pml4_addr; // Set the CR3 register to the address of the PML4
    sregs.cr4 = CR4_PAE; // Enable PAE
    sregs.cr0 = CR0_PE | CR0_PG; // Enable protected mode and paging
    sregs.efer = EFER_LMA | EFER_LME; // Enable long mode

    // Set up the 64-bit code segment
    setup_64bit_code_segment(&sregs);

    // Set the special registers for the virtual CPU
    if (ioctl(vm->vm_vcpu, KVM_SET_SREGS, &sregs) < 0) {
        // Print an error message if the ioctl call fails
        perror("ERROR: Failed ioctl KVM_SET_SREGS\n");
        fprintf(stderr, "KVM_SET_SREGS: %s\n", strerror(errno));
        return -1;
    }

    return page;
}

/**
 * Sets up the general-purpose registers for the guest VM by issuing ioctl calls to KVM_GET_REGS and KVM_SET_REGS.
 *
 * @param vm Pointer to the guest structure.
 * @return 0 on success, -1 on failure.
 */
int setup_registers(struct guest* vm) {
    struct kvm_regs regs;

    // Get the general-purpose registers of the virtual CPU
    if (ioctl(vm->vm_vcpu, KVM_GET_REGS, &regs) < 0) {
        // Print an error message if the ioctl call fails
        perror("ERROR: Failed ioctl KVM_GET_REGS\n");
        fprintf(stderr, "KVM_GET_REGS %s\n", strerror(errno));
        return -1;
    }

    // Clear the registers
    memset(&regs, 0, sizeof(regs));

    regs.rflags = 2; // Set the RFLAGS register
    regs.rip = 0; // Set the instruction pointer to 0
    regs.rsp = 1 << 21; // Set the stack pointer

    // Set the general-purpose registers for the virtual CPU
    if (ioctl(vm->vm_vcpu, KVM_SET_REGS, &regs) < 0) {
        // Print an error message if the ioctl call fails
        perror("ERROR: Failed ioctl KVM_SET_REGS\n");
        fprintf(stderr, "KVM_SET_REGS %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Sets up a pseudoterminal for the guest VM.
 *
 * @param vm Pointer to the guest structure.
 * @return 0 on success, -1 on failure.
 */
int setup_terminal(struct guest* vm) {
    // Open a pseudoterminal
    if (openpty(&vm->pty_master, &vm->pty_slave, NULL, NULL, NULL) != 0) {
        // Print an error message if the pseudoterminal cannot be opened
        perror("ERROR: Failed to open pseudoterminal\n");
        fprintf(stderr, "openpty: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/**
 * Handles the HALT exit reason by printing a message.
 *
 * @param vm Pointer to the guest structure.
 * @return 1 to indicate the VM should stop running.
 */
int exit_halt(struct guest* vm) {
    printf("KVM_EXIT_HLT\n");
    return 1;
}

// Semaphore for synchronizing file operations
sem_t file_mutex;

/**
 * Initializes a new file structure and returns a pointer to it.
 *
 * @return Pointer to the newly allocated file structure.
 */
struct file* init_file() {
    // Allocate memory for a new file structure
    struct file* new_file = (struct file*)malloc(sizeof(struct file));
    if (new_file == NULL) {
        // Print an error message if memory allocation fails
        perror("ERROR: Failed to allocate new file\n");
        exit(EXIT_FAILURE);
    }

    // Initialize the file structure fields
    new_file->cnt = 0;
    new_file->next = NULL;
    new_file->flags = -1;
    new_file->mode = -1;
    new_file->fd = -1;

    return new_file;
}

/**
 * Starts a file operation (open, close, read, write) by setting the appropriate lock and initializing the file structure if needed.
 *
 * @param vm Pointer to the guest structure.
 * @param operation The file operation to start (OPEN, CLOSE, READ, WRITE).
 * @return 0 on success.
 */
int start_file_operation(struct guest* vm, int operation) {
    // Lock the semaphore to synchronize file operations
    sem_wait(&file_mutex);
    vm->lock = operation;

    if (operation == OPEN) {
        // Initialize a new file structure if the operation is OPEN
        struct file* new_file = init_file();
        *vm->file_indirect = new_file;
        vm->file_indirect = &new_file->next;
        vm->current_file = new_file;
    }

    return 0;
}

/**
 * Ends a file operation by unlocking the semaphore and resetting the lock and current file pointer.
 *
 * @param vm Pointer to the guest structure.
 * @return 0 on success.
 */
int end_file_operation(struct guest* vm) {
    // Unlock the semaphore to allow other file operations
    sem_post(&file_mutex);
    vm->lock = 0;
    vm->current_file = NULL;
    return 0;
}

/**
 * Checks if the file path exists and opens it if it does.
 *
 * @param vm Pointer to the guest structure.
 * @return File descriptor of the opened file, -1 if the file does not exist.
 */
int check_path_exists(struct guest* vm) {
    char path[200];
    // Construct the file path using the VM ID and file name
    sprintf(path, "vm_%d_", vm->id);
    strcat(path, vm->current_file->ime);
    // Check if the file exists and open it
    if (access(path, F_OK) == 0) {
        return open(path, vm->current_file->flags, vm->current_file->mode);
    } else {
        return -1;
    }
}

/**
 * Creates a local copy of the file for the guest VM.
 *
 * @param vm Pointer to the guest structure.
 */
void create_local_copy(struct guest* vm) {
    char path[200];
    // Construct the file path using the VM ID and file name
    sprintf(path, "vm_%d_", vm->id);
    strcat(path, vm->current_file->ime);
    // Create the local copy of the file
    open(path, O_CREAT, 0777);
}

/**
 * Handles setting the flags and mode for an opened file operation.
 *
 * @param vm Pointer to the guest structure.
 * @param data Flags or mode for the file operation.
 * @return 0 on success.
 */
int opened_file_op_flags(struct guest* vm, int data) {
    if (vm->current_file->flags == -1) {
        // Set the flags if they are not already set
        vm->current_file->flags = data;
    } else {
        // Set the mode and open the file if the flags are already set
        vm->current_file->mode = data;
        int local_fd = check_path_exists(vm);

        if (local_fd < 0) {
            // If the file does not exist, create a local copy if needed
            if (vm->current_file->flags & (O_RDWR | O_WRONLY | O_TRUNC | O_APPEND)) {
                create_local_copy(vm);
                vm->current_file->fd = check_path_exists(vm);
            } else {
                // Open the file with the specified flags and mode
                vm->current_file->fd = open(vm->current_file->ime, vm->current_file->flags, vm->current_file->mode);
            }
        } else {
            // Use the existing file descriptor if the file exists
            vm->current_file->fd = local_fd;
        }
    }

    return 0;
}

/**
 * Sends the file descriptor of the currently opened file to the guest VM.
 *
 * @param vm Pointer to the guest structure.
 * @return 0 on success.
 */
int opened_file_op_send_fd(struct guest* vm) {
    *((int*)((char*)vm->kvm_run + vm->kvm_run->io.data_offset)) = vm->current_file->fd;
    return end_file_operation(vm);
}

/**
 * Handles setting the name for an opened file operation.
 *
 * @param vm Pointer to the guest structure.
 * @param data Character data for the file name.
 * @return 0 on success.
 */
int opened_file_op_name(struct guest* vm, char data) {
    vm->current_file->ime[vm->current_file->cnt++] = data;
    return 0;
}

/**
 * Retrieves the file descriptor for a given file and sets it as the current file.
 *
 * @param vm Pointer to the guest structure.
 * @param data File descriptor.
 * @return 0 on success.
 */
int get_file_descriptor(struct guest* vm, int data) {
    // Iterate through the file list to find the file with the specified file descriptor
    for (struct file* current = vm->file_head; current; current = current->next) {
        if (current->fd == data) {
            vm->current_file = current;
            break;
        }
    }

    return 0;
}

/**
 * Handles closing a file and updating the file list.
 *
 * @param vm Pointer to the guest structure.
 * @return 0 on success.
 */
int close_op_status(struct guest* vm) {
    int status;
    if (vm->current_file == NULL) status = -1;
    else status = close(vm->current_file->fd);

    // Remove the file from the file list
    for (struct file** indirect = &vm->file_head; *indirect; indirect = &(*indirect)->next) {
        if (*indirect == vm->current_file) {
            *indirect = vm->current_file->next;
            break;
        }
    }

    // Free the file structure
    free(vm->current_file);
    *((int*)((char*)vm->kvm_run + vm->kvm_run->io.data_offset)) = status;

    return 0;
}

/**
 * Reads a character from a file and sends it to the guest VM.
 *
 * @param vm Pointer to the guest structure.
 * @return 0 on success.
 */
int read_file(struct guest* vm) {
    if (vm->current_file == NULL) {
        *((char*)vm->kvm_run + vm->kvm_run->io.data_offset) = EOF;
        return 0;
    }

    char c;
    int status = read(vm->current_file->fd, &c, 1);
    *((char*)vm->kvm_run + vm->kvm_run->io.data_offset) = status == 1 ? c : EOF;

    return 0;
}

/**
 * Writes a character to a file.
 *
 * @param vm Pointer to the guest structure.
 * @param data Character to write.
 * @return 0 on success.
 */
int write_file(struct guest* vm, char data) {
    if (vm->current_file == NULL) {
        *((char*)vm->kvm_run + vm->kvm_run->io.data_offset) = EOF;
        return 0;
    }

    write(vm->current_file->fd, &data, 1);
    return 0;
}

/**
 * Handles file operations (open, close, read, write) for the guest VM.
 *
 * @param vm Pointer to the guest structure.
 * @return 0 on success.
 */
int handle_file(struct guest* vm) {
    if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT && vm->kvm_run->io.size == sizeof(int)) {
        int data = *((int*)((char*)vm->kvm_run + vm->kvm_run->io.data_offset));

        if (vm->lock == 0) {
            return start_file_operation(vm, data);
        } else if (vm->lock == OPEN) {
            return opened_file_op_flags(vm, data);
        } else if (data == FINISH) {
            return end_file_operation(vm);
        } else {
            return get_file_descriptor(vm, data);
        }
    } else if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT && vm->kvm_run->io.size == sizeof(char)) {
        char data = *((char*)vm->kvm_run + vm->kvm_run->io.data_offset);
        if (vm->lock == OPEN) {
            return opened_file_op_name(vm, data);
        } else if (vm->lock == WRITE) {
            return write_file(vm, data);
        }
    } else if (vm->kvm_run->io.direction == KVM_EXIT_IO_IN && vm->kvm_run->io.size == sizeof(int)) {
        if (vm->lock == CLOSE) {
            return close_op_status(vm);
        } else if (vm->lock == OPEN) {
            return opened_file_op_send_fd(vm);
        }
    } else if (vm->kvm_run->io.direction == KVM_EXIT_IO_IN && vm->kvm_run->io.size == sizeof(char)) {
        if (vm->lock == READ) {
            return read_file(vm);
        }
    }

    return 0;
}

/**
 * Handles IO exits for the guest VM, including pseudoterminal communication and file operations.
 *
 * @param vm Pointer to the guest structure.
 * @return 0 on success, -1 on failure.
 */
int exit_io(struct guest* vm) {
    if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT && vm->kvm_run->io.port == 0xE9) {
        char c = *((char*)vm->kvm_run + vm->kvm_run->io.data_offset);
        write(vm->pty_master, &c, vm->kvm_run->io.size);
        return 0;
    } else if (vm->kvm_run->io.direction == KVM_EXIT_IO_IN && vm->kvm_run->io.port == 0xE9) {
        char c;
        read(vm->pty_master, &c, sizeof(char));
        *((char*)vm->kvm_run + vm->kvm_run->io.data_offset) = c;
        return 0;
    } else if (vm->kvm_run->io.port == 0x278) {
        handle_file(vm);
    } else {
        fprintf(stderr, "Invalid port %d\n", vm->kvm_run->io.port);
        return -1;
    }
}

/**
 * Handles internal errors for the guest VM.
 *
 * @param vm Pointer to the guest structure.
 * @return -1 to indicate an error.
 */
int exit_internal_error(struct guest* vm) {
    printf("ERROR: Internal error: suberror = 0x%x\n", vm->kvm_run->internal.suberror);
    return -1;
}

/**
 * Handles shutdown exits for the guest VM.
 *
 * @param vm Pointer to the guest structure.
 * @return 1 to indicate the VM should stop running.
 */
int exit_shutdown(struct guest* vm) {
    printf("Shutdown\n");
    return 1;
}

// Typedef for the exit handlers
typedef int (*Handler)(struct guest* vm);

// Array of exit handlers
static Handler handlers[] = {
    NULL, NULL, &exit_io, NULL, NULL, &exit_halt,
    NULL, NULL, &exit_shutdown, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL,
    &exit_internal_error
};

/**
 * Runs the guest VM in a loop, handling exit reasons using the handlers array.
 *
 * @param par Pointer to the guest structure.
 * @return NULL on completion.
 */
void* run_guest(void* par) {
    struct guest* vm = (struct guest*)par;
    int stop = 0;
    int ret;

    while (stop == 0) {
        // Run the virtual CPU
        ret = ioctl(vm->vm_vcpu, KVM_RUN, 0);
        if (ret < 0) {
            // Print an error message if the ioctl call fails
            perror("ERROR: Failed ioctl KVM_RUN\n");
            fprintf(stderr, "KVM_RUN: %s\n", strerror(errno));
            return NULL;
        }

        int exit_reason = vm->kvm_run->exit_reason; // Get the exit reason

        // Call the appropriate handler for the exit reason
        if (handlers[exit_reason]) {
            stop = handlers[exit_reason](vm);
        } else {
            printf("Unknown exit reason %d\n", exit_reason);
            stop = -1;
        }
    }

    return NULL;
}

/**
 * Starts a guest VM in a new thread and loads the guest image into memory.
 *
 * @param vm Pointer to the guest structure.
 * @param img Pointer to the guest image file.
 * @param starting_address Starting address for loading the image.
 * @return Thread handle on success, -1 on failure.
 */
pthread_t start_guest(struct guest* vm, FILE* img, int starting_address) {
    pthread_t handle;

    // Load the guest image into memory
    char* p = vm->mem + starting_address;
    while (feof(img) == 0) {
        int r = fread(p, 1, 1024, img);
        p += r;
    }

    // Create a new thread to run the guest VM
    if (pthread_create(&handle, NULL, &run_guest, vm) == 0) {
        return handle;
    } else {
        return -1;
    }
}

/**
 * Initializes the guest VM by creating the guest, memory region, vCPU, and setting up long mode and registers.
 *
 * @param hypervisor Pointer to the hypervisor structure.
 * @param vm Pointer to the guest structure.
 * @param mem_size Size of the memory allocated for the guest.
 * @param page_size Page size (2MB or 4KB).
 * @param img Pointer to the guest image file.
 * @return Starting address of the loaded image on success, -1 on failure.
 */
int init_guest(struct hypervisor* hypervisor, struct guest* vm, size_t mem_size, enum PageSize page_size, FILE* img) {
    static int incId = 0;

    int starting_address;

    if (create_guest(hypervisor, vm) < 0) return -1;
    if (create_memory_region(vm, mem_size) < 0) return -1;
    if (create_vcpu(vm) < 0) return -1;
    if (create_kvm_run(hypervisor, vm) < 0) return -1;
    if ((starting_address = setup_long_mode(vm, mem_size, page_size)) < 0) return -1;
    if (setup_registers(vm) < 0) return -1;
    vm->lock = 0;
    vm->file_head = NULL;
    vm->file_indirect = &vm->file_head;
    vm->current_file = NULL;
    vm->id = incId++;

    return starting_address;
}

/**
 * Main function to parse command line arguments, initialize the hypervisor and guest VMs, and start running the guests.
 * Supports multiple guests running in separate threads.
 *
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return 0 on success, exits with EXIT_FAILURE on failure.
 */
int main(int argc, char* argv[]) {
    int opt;
    int memory = 0; // Memory size in bytes
    enum PageSize page_size; // Page size
    struct hypervisor hypervisor;
    int starting_address;

    // Define the command line options
    struct option long_options[] = {
        {"memory", required_argument, 0, 'm'},
        {"page", required_argument, 0, 'p'},
        {"guest", no_argument, 0, 'g'},
        {0, 0, 0, 0,}
    };

    // Parse the command line options
    while ((opt = getopt_long(argc, argv, "m:p:g", long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                memory = atoi(optarg) * 1024 * 1024; // Convert memory size to bytes
                break;
            case 'p':
                page_size = (atoi(optarg) == 4) ? KB4 : MB2; // Set the page size
                break;
            case 'g':
                break;
        }
    }

    // Initialize the hypervisor
    if (init_hypervisor(&hypervisor) < 0) {
        printf("ERROR: Unable to initialize hypervisor\n");
        exit(EXIT_FAILURE);
    }

    int num_of_vms = argc - optind; // Number of guest VMs
    pthread_t* vms = (pthread_t*)malloc(sizeof(pthread_t) * num_of_vms); // Array of thread handles for the guest VMs

    // Initialize the semaphore for synchronizing file operations
    if (sem_init(&file_mutex, 0, 1) < 0) {
        perror("ERROR: Failed sem_init\n");
        fprintf(stderr, "sem_init: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    for (int i = optind; i < argc; i++) {
        // Open the guest image file
        FILE* img = fopen(argv[i], "r");
        if (img == NULL) {
            printf("ERROR: Unable to open file %s\n", argv[i]);
            exit(EXIT_FAILURE);
        }

        // Allocate memory for the guest VM structure
        struct guest* vm = malloc(sizeof(struct guest));
        if (vm == NULL) {
            printf("ERROR: Memory allocation failed\n");
            printf("fopen: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        // Initialize the guest VM
        if ((starting_address = init_guest(&hypervisor, vm, memory, page_size, img)) < 0) {
            printf("ERROR: Unable to initialize guest\n");
            exit(EXIT_FAILURE);
        }

        // Start the guest VM
        pthread_t handle = start_guest(vm, img, starting_address);
        vms[argc - i - 1] = handle;
    }
	
	
    // Wait for all guests VMs to finish
    for (int i = 0; i < num_of_vms; i++) {
        pthread_join(vms[i], NULL);
    }

    free(vms);
    return 0;
}
