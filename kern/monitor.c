// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>
#include <kern/pmap.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display all the outstanding stack frames", mon_backtrace},
	{ "showmappings", "Display memory mappings", mon_showmappings },
	{ "setPerm", "Set permission of a vtirual page", setPerm},
	{ "vvm", "Dump contents of certain virtual memory", vvm},
	{ "vpm", "Dump contents of certain physical memory", vpm},
};
#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < NCOMMANDS; i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t *ebp = (uint32_t*)read_ebp();
	cprintf("Stack backreace:\n");

	while (ebp != 0) {
		cprintf("ebp %08x eip %08x args %08x %08x %08x %08x %08x\n", ebp, *(ebp + 1), 
			*(ebp + 2), *(ebp + 3), *(ebp + 4), *(ebp + 5), *(ebp + 6));
		
		struct Eipdebuginfo info;
		debuginfo_eip(*(ebp + 1), &info);
		cprintf("\t%s:%d: %.*s+%d\n", info.eip_file, info.eip_line,
			info.eip_fn_namelen, info.eip_fn_name,
			*(ebp + 1) - info.eip_fn_addr);
		ebp = (uint32_t*)*ebp;
	}

	return 0;
}

/* convert a string to integer */
uintptr_t
convert(char *c) {
	int res = 0;
	int base;

	if (c[0] == '0' && c[1] == 'x') {
		base = 16;
		c += 2;
	}
	else base = 10;

	while (*c) {
		res *= base;
		if (*c <= '9') res += *c - '0';
		else res += *c - 'a' + 10;
		c++;
	}

	return res;
}

/* Display the physical page mappings to a range of virtual address */
int
mon_showmappings(int argc, char **argv, struct Trapframe *tf) {
	if (argc != 3) {
		cprintf("Usage : showmappings <begin-address> <end-address>\n");
		return 0;
	}
	
	uintptr_t begin, end, i;
	pte_t *ptet;

	begin = convert(argv[1]);
	end = convert(argv[2]);
	cprintf("Got args: 0x%08x 0x%08x\n", begin, end);

	for (i = begin; i <= end; i += PGSIZE) {
		ptet = pgdir_walk(kern_pgdir, (void*)i, 1);
		if (!ptet) {
			cprintf("Page walk error!\n");
			return 0;
		}
		cprintf("Virtual address : 0x%08x ", i);
		if (*ptet & PTE_P)
			cprintf("Physical page : 0x%08x PTE_P %d PTE_U %d PTE_W %d\n",  PTE_ADDR(*ptet), !!(*ptet & PTE_P), !!(*ptet & PTE_U), !!(*ptet & PTE_W));
		else
			cprintf("is not mapped!\n");

	}


	return 0;
}

int
setPerm(int argc, char **argv, struct Trapframe *tf) {
	if (argc != 3) {
		cprintf("Usage : setPerm <virtual-address> <permission>");
		return 0;
	}
	pte_t *ptet;
	ptet = pgdir_walk(kern_pgdir, (void*)convert(argv[1]), 1);
	*ptet &= ~0xfff;
	*ptet |= convert(argv[2]);
	return 0;
}

int
vpm(int argc, char **argv, struct Trapframe *tf) {
	if (argc != 3) {
		cprintf("Usage : vpm <physical-address> <num>");
		return 0;
	}

	int *i;
	int begin = convert(argv[1]), n = convert(argv[2]);
	int * p = KADDR(begin);
	for (i = p; i < p + n; ++i)
		cprintf("Value of 0x%08x is 0x%08x\n", PADDR(i), *i);

	return 0;
}

int
vvm(int argc, char **argv, struct Trapframe *tf) {
	if (argc != 3) {
		cprintf("Usage : vpm <virtual-address> <num>");
		return 0;
	}
	int *i;
	int begin = convert(argv[1]), n = convert(argv[2]);
	for (i = (int*)begin; i < (int*)begin + n; ++i)
		cprintf("Value of 0x%08x is 0x%08x\n", i, *i);
	return 0;
}


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < NCOMMANDS; i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
