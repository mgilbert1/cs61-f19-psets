#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include <atomic>

// kernel.cc
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

proc ptable[NPROC];             // array of process descriptors
                                // Note that `ptable[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static std::atomic<unsigned long> ticks; // # timer interrupts so far


// Memory state
//    Information about physical page with address `pa` is stored in
//    `pages[pa / PAGESIZE]`. In the handout code, each `pages` entry
//    holds an `refcount` member, which is 0 for free pages.
//    You can change this as you see fit.

pageinfo pages[NPAGES];


[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();


// kernel(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, const char* program_name);

void kernel(const char* command) {
    // initialize hardware
    init_hardware();
    log_printf("Starting WeensyOS\n");

    ticks = 1;
    init_timer(HZ);

    // clear screen
    console_clear();

    // (re-)initialize kernel page table
    for (vmiter it(kernel_pagetable);
         it.va() < MEMSIZE_PHYSICAL;
         it += PAGESIZE) {
        if (it.va() == 0) {
            // nullptr is inaccessible even to the kernel
            it.map(it.va(), 0);
        } else if (it.va() >= PROC_START_ADDR || it.va() == CONSOLE_ADDR) {
            it.map(it.va(), PTE_P | PTE_W | PTE_U);
        } else {
            it.map(it.va(), PTE_P | PTE_W );
        }
    }

    // set up process descriptors
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (command && program_loader(command).present()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }

    // Switch to the first process using run()
    run(&ptable[1]);
}


// kalloc(sz)
//    Kernel memory allocator. Allocates `sz` contiguous bytes and
//    returns a pointer to the allocated memory, or `nullptr` on failure.
//
//    The returned memory is initialized to 0xCC, which corresponds to
//    the x86 instruction `int3` (this may help you debug). You'll
//    probably want to reset it to something more useful.
//
//    On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
//    the allocation fails; if `sz < PAGESIZE` it allocates a whole page
//    anyway.
//
//    The handout code returns the next allocatable free page it can find.
//    It never reuses pages or supports freeing memory (you'll change that).

static uintptr_t next_alloc_pa;

void* kalloc(size_t sz) {
    // log_printf("kalloc -> ");
    if (sz > PAGESIZE) {
        log_printf("exit kalloc1\n");
        return nullptr;
    }

    next_alloc_pa = 0;
    while (next_alloc_pa < MEMSIZE_PHYSICAL) {
        uintptr_t pa = next_alloc_pa;
        next_alloc_pa += PAGESIZE;

        if (allocatable_physical_address(pa)
            && !pages[pa / PAGESIZE].used()) {
            pages[pa / PAGESIZE].refcount = 1;
            memset((void*) pa, 0xCC, PAGESIZE);
            // log_printf("exit kalloc2\n");
            return (void*) pa;
        }
    }
    // log_printf("exit kalloc3\n");
    return nullptr;
}


// kfree(kptr)
//    Free `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr` does nothing.

void kfree(void* kptr) {
    // log_printf("kfree\n");
    //(void) kptr;
    //assert(false /* your code here */);
    if (!kptr || pages[(uintptr_t) kptr / PAGESIZE].refcount == 0)
        return;

    // set refcount to 0 (means page is freed)

    pages[(uintptr_t) kptr / PAGESIZE].refcount -= 1;

    // reset data? not sure if necessary
    //memset((void*) kptr, 0, PAGESIZE);
}

void freePT(x86_64_pagetable* pt);

// process_setup(pid, program_name)
//    Load application program `program_name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, const char* program_name) {
    init_process(&ptable[pid], 0);

    log_printf("start of process %d \n", pid);

    // initialize process page table
    void* ptr = kalloc(PAGESIZE);
    if (!ptr) {
        log_printf("panic in process_setup\n");
        panic(nullptr);
    }
    x86_64_pagetable* addr = (x86_64_pagetable*) ptr;
    memset((void*) addr, 0, PAGESIZE);
    //sys_page_alloc(addr);

    //log_printf("addr %lu \n", (uintptr_t) addr);


    // initialize page table
    for (vmiter it(addr), it2(kernel_pagetable);
         it.va() < MEMSIZE_VIRTUAL;
         it += PAGESIZE, it2 += PAGESIZE) {

        if (it2.present()) {
            //log_printf("%p maps to %p\n", it.va(), it2.pa());
            if (it.va() < PROC_START_ADDR) {
                int r = it.try_map(it2.pa(), it2.perm());
                if (r < 0) {
                    freePT(addr);
                    return;
                }
            }
            //else
                //it.map(it2.pa(), it2.perm() & 0x6 );
            //it.map(it2.pa(), it2.perm());
        }
    }

    ptable[pid].pagetable = addr;
    //ptable[pid].pagetable = kernel_pagetable;

    // load the program
    program_loader loader(program_name);

    // allocate and map all memory
    // copy instructions and data into place
    for (loader.reset(); loader.present(); ++loader) {
        if (!loader.present()) {
            freePT(ptable[pid].pagetable);
            return;
        }

        int perm = PTE_P | PTE_U;
        if (loader.writable()) {
            perm = PTE_P | PTE_W | PTE_U;
        }
        uintptr_t counter = (uintptr_t) loader.data();
        for (uintptr_t a = round_down(loader.va(), PAGESIZE);
             a < loader.va() + loader.size();
             a += PAGESIZE) {
            void* a2 = kalloc(PAGESIZE);
            if (!a2) {
                freePT(ptable[pid].pagetable);
                return;
            }
            memset((void*) a2, 0, PAGESIZE);
            // memcpy((void*) a2, (void*) (((uintptr_t) loader.data()) + a - start), PAGESIZE);
            memcpy((void*) a2, (void*) counter, PAGESIZE);
            counter += PAGESIZE;
            //assert(!pages[a / PAGESIZE].used());
            int r = vmiter(ptable[pid].pagetable, a).try_map((uintptr_t) a2, perm);
            if (r < 0) {
                freePT(ptable[pid].pagetable);
                return;
            }
            //pages[a / PAGESIZE].refcount = 1;
        }
        //memset((void*) vmiter(&ptable[pid], loader.va()).pa(), 0, loader.size());
        //memcpy((void*) vmiter(&ptable[pid], loader.va()).pa(), loader.data(), loader.data_size());
    }

 /*   // copy instructions and data into place
    for (loader.reset(); loader.present(); ++loader) {
        if (loader.writable()) {
            memset((void*) vmiter(&ptable[pid], loader.va()).pa(), 0, loader.size());
            memcpy((void*) vmiter(&ptable[pid], loader.va()).pa(), loader.data(), loader.data_size());
        }
        else {
                    
        }
    }*/

    // mark entry point
    ptable[pid].regs.reg_rip = loader.entry();

    // allocate stack
    //uintptr_t stack_addr = PROC_START_ADDR + PROC_SIZE * pid - PAGESIZE;
    uintptr_t stack_addr = MEMSIZE_VIRTUAL - PAGESIZE;
    void* sa2 = kalloc(PAGESIZE);
    if (!sa2) {
        freePT(ptable[pid].pagetable);
        return;
    }
    //assert(!pages[stack_addr / PAGESIZE].used());
    int r = vmiter(ptable[pid].pagetable, stack_addr).try_map((uintptr_t) sa2, PTE_P | PTE_W | PTE_U);
    if (r < 0) {
        freePT(ptable[pid].pagetable);
        return;
    }
    //pages[stack_addr / PAGESIZE].refcount = 1;
    ptable[pid].regs.reg_rsp = stack_addr + PAGESIZE;

    // mark process as runnable
    ptable[pid].state = P_RUNNABLE;
}



// exception(regs)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `regs`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled when the kernel is running.

void exception(regstate* regs) {
    
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    log_printf("exception %d\n", regs->reg_intno);

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: exception %d at rip %p\n",
                current->pid, regs->reg_intno, regs->reg_rip); */

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PFERR_USER)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();

    log_printf("exception %d\n", regs->reg_intno);

    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();
        break;                  /* will not be reached */

    case INT_PF: {
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PFERR_WRITE
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, regs->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->pid, addr, operation, problem, regs->reg_rip);
        current->state = P_BROKEN;
        break;
    }

    default:
        panic("Unexpected exception %d!\n", regs->reg_intno);

    }


    // Return to the current process (or run something else).
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// syscall(regs)
//    System call handler.
//
//    The register values from system call time are stored in `regs`.
//    The return value, if any, is returned to the user process in `%rax`.
//
//    Note that hardware interrupts are disabled when the kernel is running.

int syscall_page_alloc(uintptr_t addr);
pid_t fork();
void sys_exit(pid_t p);

uintptr_t syscall(regstate* regs) {
    log_printf("syscall\n");
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: syscall %d at rip %p\n",
                  current->pid, regs->reg_rax, regs->reg_rip); */

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();

    // Actually handle the exception.
    switch (regs->reg_rax) {

    case SYSCALL_PANIC:
        log_printf("syscall panic %d \n", regs->reg_rax);
        panic(nullptr);         // does not return

    case SYSCALL_GETPID:
        log_printf("syscall get%d\n", current->regs.reg_intno);
        return current->pid;

    case SYSCALL_YIELD:
    log_printf("syscall yield %d\n", current->regs.reg_intno);
        current->regs.reg_rax = 0;
        schedule();             // does not return

    case SYSCALL_PAGE_ALLOC:
    log_printf("syscall alloc %d\n", current->regs.reg_intno);
        return syscall_page_alloc(current->regs.reg_rdi);

    case SYSCALL_FORK:
    log_printf("syscall fork %d\n", current->regs.reg_intno);
        return fork();

    case SYSCALL_EXIT:
    log_printf("syscall exit %d\n", current->regs.reg_intno);
        sys_exit(current->pid);
        schedule();             // does not return

    default:
        panic("Unexpected system call %ld!\n", regs->reg_rax);

    }

    panic("Should not get here!\n");
}


// syscall_page_alloc(addr)
//    Handles the SYSCALL_PAGE_ALLOC system call. This function
//    should implement the specification for `sys_page_alloc`
//    in `u-lib.hh` (but in the handout code, it does not).

int syscall_page_alloc(uintptr_t addr) {
    log_printf("syscall_page_alloc %lu -> ", addr);
    //assert(!pages[addr / PAGESIZE].used());
    //kfree((void*) addr);
    if (addr < PROC_START_ADDR || addr >= MEMSIZE_VIRTUAL || addr % PAGESIZE != 0)
    {
        log_printf("bad spa1\n");
        return -1;
    }
    //pages[addr / PAGESIZE].refcount = 1;
    void* a2 = kalloc(PAGESIZE);
    if (!a2) {
        log_printf("bad spa2\n");
        return -1;
    }
    memset((void*) a2, 0, PAGESIZE);
    int r = vmiter(current->pagetable, addr).try_map((uintptr_t) a2, PTE_P | PTE_W | PTE_U);
    if (r < 0) {
        kfree((void*) a2);
        log_printf("bad spa3\n");
        return -1;
    }
    log_printf("good spa1\n");
    return 0;
}


// delete page table
void freePT(x86_64_pagetable* pt) {
    log_printf("freePT -> ");
    for (vmiter it(pt); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) {
        if (it.present() && it.user() && it.writable())
            kfree((void*) it.pa());
    }
    for (ptiter it(pt); it.va() < MEMSIZE_VIRTUAL; it.next()) {
        if (it.active())
            kfree((void*) it.pa());
    }
    kfree((void*) pt);
    log_printf("end freePT -> ");
}

// fork

pid_t fork() {
    log_printf("fork -> ");
    int index = -1;
    for (int i = 1; i < NPROC; i++) {
        //log_printf("ptable: %d\n", ptable[i].state);
        if (ptable[i].state == P_FREE)
        {
            index = i;
            break;
        }
    }
    log_printf("index: %d -> ", index);
    if (index == -1)
        return -1;

    x86_64_pagetable* curr_pt = current->pagetable;
    x86_64_pagetable* new_pt = (x86_64_pagetable*) kalloc(PAGESIZE);
    if (!new_pt)
        return -1;
        //sys_exit(index);

    log_printf("allocated pt -> ");

    memset((void*) new_pt, 0, PAGESIZE);
    ptable[index].pagetable = new_pt;

    log_printf("copied pt -> ");

    for (vmiter it(curr_pt);
         it.va() < MEMSIZE_VIRTUAL;
         it += PAGESIZE) {
        if (it.present()) {
            if (it.va() < PROC_START_ADDR) {
                int r = vmiter(ptable[index].pagetable, (uintptr_t) it.va()).try_map(it.pa(), it.perm());
                if (r < 0) {
                    log_printf(" -- exit1 --");
                    //freePT(new_pt);
                    sys_exit(index);
                    return -1;
                    log_printf(" -- post --");
                }
                //log_printf("shared page: %d\n", (uintptr_t) it.pa());
                //pages[it.pa() / PAGESIZE].refcount += 1;
            }
            else if(it.writable()) {
                void* new_page = kalloc(PAGESIZE);
                if (!new_page) {
                    log_printf(" -- exit2 --");
                    //freePT(new_pt);
                    sys_exit(index);
                    return -1;
                    log_printf(" -- post --");
                }
                memcpy(new_page, (void*) it.pa(), PAGESIZE);
                int r = vmiter(ptable[index].pagetable, (uintptr_t) it.va()).try_map((uintptr_t) new_page, it.perm());
                if (r < 0) {
                    log_printf(" -- exit3 --");
                   // freePT(new_pt);
                    sys_exit(index);
                    return -1;
                    log_printf(" -- post --");
                }
            }
            else {
                //log_printf("read only\n");
                int r = vmiter(ptable[index].pagetable, (uintptr_t) it.va()).try_map((uintptr_t) it.pa(), it.perm());
                if (r < 0) {
                    log_printf(" -- exit4 --");
                    //freePT(new_pt);
                    sys_exit(index);
                    return -1;
                    log_printf(" -- post --");
                }
                // log_printf("shared page: %d\n", (uintptr_t) it.pa());
                pages[it.pa() / PAGESIZE].refcount += 1;
            }
        }
    }
    
    log_printf("copied pages ->");

    memcpy((void*) &(ptable[index].regs), (void*) &(current->regs), sizeof(regstate));
    ptable[index].regs.reg_rax = 0;
    
    log_printf("copied regs ->");

    ptable[index].state = P_RUNNABLE;

    log_printf(" end  fork\n");

    return index;
}

// sys_exit

void sys_exit(pid_t p) {
    log_printf("sys_exit -> ");

    freePT(ptable[p].pagetable);
    ptable[p].state = P_FREE;
    log_printf("se  %d ->", ptable[p].regs.reg_intno);
    log_printf("end sys_exit\n");

    // free code, data, heap, stack pages of current process
    // x86_64_pagetable* pt = current->pagetable;
    // log_printf("refcount: %d\n", pages[(uintptr_t) pt / PAGESIZE].refcount);

    // // for (ptiter it(pt, 0); it.va() < MEMSIZE_VIRTUAL; it.next()) {
    // //     //log_printf("1\n");
    // //     //log_printf("[%p, %p): ptp at va %p, pa %p\n",
    // //           //   it.va(), it.last_va(), it.kptr(), it.pa());
    // // }

    // for (vmiter it(pt); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) {
    //     //log_printf("vmiter\n");
    //     if (it.present() && it.writable() && it.user()) {
    //         // if (pages[it.pa() / PAGESIZE].refcount == 1)
    //         kfree((void*) it.pa());
    //         // else
    //            // pages[it.pa() / PAGESIZE].refcount -= 1;
    //     }
    // }

    // log_printf("freed vmiter\n");

    // // for (ptiter it(pt, 0); it.va() < MEMSIZE_VIRTUAL; it.next()) {
    // //   //  log_printf("1\n");
    // //     //log_printf("[%p, %p): ptp at va %p, pa %p\n",
    // //             // it.va(), it.last_va(), it.kptr(), it.pa());
    // // }

    // for (ptiter it(pt); it.va() < MEMSIZE_VIRTUAL; it.next()) {
    //     log_printf("[%p, %p): ptp at va %p, pa %p\n", it.va(), it.last_va(), it.kptr(), it.pa());
    //     if (it.active()) {
    //         // x86_64_pagetable* curr_page = it.ptp();
    //         // if (pages[it.pa() / PAGESIZE].refcount == 1)
    //         kfree((void*) it.pa());
    //         // else
    //            // pages[it.pa() / PAGESIZE].refcount -= 1;
    //     }
    // }

    // log_printf("freed ptiter\n");

    // // if (pages[(uintptr_t) pt / PAGESIZE].refcount == 1)
    // kfree((void*) pt);

    // current->state = P_FREE;
    // // else
    // //     pages[(uintptr_t) pt / PAGESIZE].refcount -= 1;

    // log_printf("done with exit\n");
}

// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule() {
    log_printf("schedule -> ");
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % NPROC;
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
            log_printf("schedule run -> ");
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
            log_printf("spins: %u\n", spins);
        }
    }
    log_printf("end schedule\n");
}


// run(p)
//    Run process `p`. This involves setting `current = p` and calling
//    `exception_return` to restore its page table and registers.

void run(proc* p) {
    log_printf("run - ");
    assert(p->state == P_RUNNABLE);
    current = p;

    log_printf("runnable -rax: %d - ", current->regs.reg_rax);

    // Check the process's current pagetable.
    check_pagetable(p->pagetable);

    log_printf("checked - \n");

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(p);

    log_printf("bad\n");

    // should never get here
    while (true) {
    }
}


// memshow()
//    Draw a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.

void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % NPROC;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < NPROC; ++search) {
        if (ptable[showing].state != P_FREE
            && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % NPROC;
        }
    }

    extern void console_memviewer(proc* vmp);
    console_memviewer(p);
}
