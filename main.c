#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <capstone/capstone.h>

// ansi colors
#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_BOLD_RED "\033[1;31m"
#define ANSI_BOLD_CYAN "\033[1;36m"
#define ANSI_BOLD_YELLOW "\033[1;33m"

void print_cpu_registers(struct user_regs_struct *regs) {
    printf("\n" ANSI_BOLD_CYAN "--- CPU Registers State ---" ANSI_RESET "\n");
    #define P_REG(name, val) printf(ANSI_YELLOW "%-3s:" ANSI_RESET " 0x%016llx  ", name, (unsigned long long)val)
    P_REG("RAX", regs->rax); P_REG("RBX", regs->rbx); P_REG("RCX", regs->rcx); printf("\n");
    P_REG("RDX", regs->rdx); P_REG("RSI", regs->rsi); P_REG("RDI", regs->rdi); printf("\n");
    P_REG("RBP", regs->rbp); P_REG("RSP", regs->rsp); 
    printf(ANSI_BOLD_RED "RIP:" ANSI_RESET " " ANSI_RED "0x%016llx" ANSI_RESET "\n", (unsigned long long)regs->rip);
    P_REG("R8 ", regs->r8);  P_REG("R9 ", regs->r9);  P_REG("R10", regs->r10); printf("\n");
    P_REG("R11", regs->r11); P_REG("R12", regs->r12); P_REG("R13", regs->r13); printf("\n");
    P_REG("R14", regs->r14); P_REG("R15", regs->r15); P_REG("EFL", regs->eflags); printf("\n");
}

unsigned long get_base_address(pid_t pid) {
    char filename[64];
    char line[256];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    FILE *fp = fopen(filename, "r");
    if (!fp) return 0;
    unsigned long addr = 0;
    if (fgets(line, sizeof(line), fp)) {
        sscanf(line, "%lx-", &addr);
    }
    fclose(fp);
    return addr;
}

void print_assembly_instruction(unsigned char *bytes, int length, uint64_t address) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf(ANSI_RED "Error during Capostone Engine init\n" ANSI_RESET);
        return;
    }

    // capstone needs "address" to compute the relative jumps for JMP instructions
    count = cs_disasm(handle, bytes, length, address, 0, &insn);

    if (count > 0) {
        // instruction that caused the crash
        printf("   ASM: " ANSI_BOLD_YELLOW "%-6s %s" ANSI_RESET "\n", 
               insn[0].mnemonic, insn[0].op_str);

        // the next 3 instructions
        for (int i = 1; i <= 3; i++) printf("   ASM: " "%-6s %s" ANSI_RESET "\n", insn[1].mnemonic, insn[1].op_str);
    
        cs_free(insn, count);
    } else {
        printf(ANSI_RED "Impossible disassemble instruction at 0x%lx\n" ANSI_RESET, address);
    }

    cs_close(&handle);
}

void print_c_context(const char *exe_name, long relative_addr) {
    // check if we have addr2line on the system
    if (access("/usr/bin/addr2line", X_OK) != 0 && access("/bin/addr2line", X_OK) != 0) {
        printf(ANSI_YELLOW "\n   [WARN] 'addr2line' utility not found on the system. Please install 'binutils'\n" ANSI_RESET);
        printf("C Source mapping will not be done\n");
        return;
    }

    char command[512];
    snprintf(command, sizeof(command), "addr2line -e %s -C -s %lx", exe_name, relative_addr);
    
    FILE *fp = popen(command, "r");
    if (!fp) return;

    char result[256];
    if (fgets(result, sizeof(result), fp)) {
        char *colon = strchr(result, ':');
        if (colon) {
            *colon = '\0'; 
            char *filename = result;
            int target_line = atoi(colon + 1);

            if (strcmp(filename, "??") == 0 || target_line == 0) {
                printf(ANSI_RED "   [WARN] Debug symbols not found in binary.\nPlease recompile it with '-g' flag\n" ANSI_RESET);
            } else {
                printf("\n" ANSI_BOLD_CYAN "--- C Source Analysis ---" ANSI_RESET "\n");
                printf("   > File: " ANSI_MAGENTA "%s" ANSI_RESET ", Row: " ANSI_BOLD "%d" ANSI_RESET "\n", filename, target_line);
                
                FILE *src_file = fopen(filename, "r");
                if (src_file) {
                    char src_line[1024];
                    int current_line = 0;
                    printf(ANSI_BLUE "   --------------------------------------------------" ANSI_RESET "\n");
                    while (fgets(src_line, sizeof(src_line), src_file)) {
                        current_line++;
                        if (current_line >= target_line - 2 && current_line <= target_line + 1) {
                            src_line[strcspn(src_line, "\n")] = 0;
                            if (current_line == target_line)
                                printf(ANSI_BOLD_RED "-> %4d | %s" ANSI_RESET "\n", current_line, src_line);
                            else
                                printf(ANSI_GREEN "   %4d" ANSI_RESET " | %s\n", current_line, src_line);
                        }
                        if (current_line > target_line + 1) break;
                    }
                    printf(ANSI_BLUE "   --------------------------------------------------" ANSI_RESET "\n");
                    fclose(src_file);
                }
            }
        }
    }
    pclose(fp);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Bad arguments.\nUsage: %s <target_executable> [executable_args]\n", argv[0]);
        return 1;
    }

    pid_t child = fork();

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        exit(1);
    } else if (child > 0) {
        int status;
        struct user_regs_struct regs;
        siginfo_t siginfo;

        while (1) {
            waitpid(child, &status, 0);
            if (WIFEXITED(status)) break;

            if (WIFSTOPPED(status)) {
                int signal = WSTOPSIG(status);
                if (signal == SIGTRAP) {
                    ptrace(PTRACE_CONT, child, NULL, NULL);
                    continue;
                }

                if (signal == SIGSEGV) {
                    printf("\n  _______  ______    _______  _______  __   __  _______  __   __  _______  ______    ______  \n"
                    "|       ||    _ |  |   _   ||       ||  | |  ||       ||  | |  ||   _   ||    _ |  |      | \n"
                    "|       ||   | ||  |  |_|  ||  _____||  |_|  ||    ___||  | |  ||  |_|  ||   | ||  |  _    |\n"
                    "|       ||   |_||_ |       || |_____ |       ||   | __ |  |_|  ||       ||   |_||_ | | |   |\n"
                    "|      _||    __  ||       ||_____  ||       ||   ||  ||       ||       ||    __  || |_|   |\n"
                    "|     |_ |   |  | ||   _   | _____| ||   _   ||   |_| ||       ||   _   ||   |  | ||       |\n"
                    "|_______||___|  |_||__| |__||_______||__| |__||_______||_______||__| |__||___|  |_||______| \n"
                    );


                    printf("\n" ANSI_BOLD_RED "=========================================" ANSI_RESET);
                    printf("\n" ANSI_BOLD_RED "--- SEGMENTATION FAULT DETECTED ---" ANSI_RESET);
                    printf("\n" ANSI_BOLD_RED "--- CRASH ANALYSIS ---" ANSI_RESET);
                    printf("\n" ANSI_BOLD_RED "=========================================" ANSI_RESET "\n");

                    ptrace(PTRACE_GETREGS, child, NULL, &regs);
                    ptrace(PTRACE_GETSIGINFO, child, NULL, &siginfo);

                    unsigned long long rip = (unsigned long long)regs.rip;
                    unsigned long base_addr = get_base_address(child);
                    long relative_addr = (long)(rip - base_addr);
                    if (base_addr == 0 || rip < base_addr) relative_addr = rip;

                    printf("\n" ANSI_BOLD_CYAN "--- General Info ---" ANSI_RESET "\n");
                    printf("Target Program Name: " ANSI_YELLOW "%s\n" ANSI_RESET, argv[1]);
                    printf("Crash Address (RIP): " ANSI_RED "0x%llx" ANSI_RESET "\n", rip);
                    printf("Memory Access (ADDR): " ANSI_RED "%p" ANSI_RESET "\n", siginfo.si_addr);

                    print_cpu_registers(&regs);

                    // read instruction bytes
                    unsigned char instr_bytes[16];
                    long w1 = ptrace(PTRACE_PEEKTEXT, child, rip, NULL);
                    long w2 = ptrace(PTRACE_PEEKTEXT, child, rip + 8, NULL);
                    memcpy(instr_bytes, &w1, 8);
                    memcpy(instr_bytes + 8, &w2, 8);
                    
                    printf("\n" ANSI_BOLD_CYAN "--- Assembly Instructions Analysis ---" ANSI_RESET "\n");

                    // we need RIP to correct to compute offsets
                    print_assembly_instruction(instr_bytes, 15, rip);

                    print_c_context(argv[1], relative_addr);
                    
                    puts("");
                    break;
                }
                ptrace(PTRACE_CONT, child, NULL, signal);
            }
        }
    }
}
