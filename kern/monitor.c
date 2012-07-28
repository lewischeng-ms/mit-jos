// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>

#include <kern/pmap.h>

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
	{ "backtrace", "Display backtrace of the stack", mon_backtrace },
	{ "showmappings", "Display physical page mappings and permission bits", mon_showmap },
	{ "xm", "Shorthand for showmappings", mon_showmap },
	{ "showphyspage", "Display contents of physical pages", mon_showpp },
	{ "xp", "Shorthand for showphyspage", mon_showpp },
	{ "showvirtpage", "Display contents of virtual pages", mon_showvp },
	{ "xv", "Shorthand for showvirtpage", mon_showvp }
};

#define NCOMMANDS (sizeof(commands)/sizeof(commands[0]))

unsigned read_eip();

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
	extern char entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		(end-entry+1023)/1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
    cprintf("Stack backtrace:\n");

    uint32_t *ebp = (uint32_t *)read_ebp();
    while (ebp) {
        uint32_t old_ebp = ebp[0];
        uint32_t ret_addr = ebp[1];
        uint32_t arg0 = ebp[2];
        uint32_t arg1 = ebp[3];
        uint32_t arg2 = ebp[4];
        uint32_t arg3 = ebp[5];
        uint32_t arg4 = ebp[6];

        struct Eipdebuginfo info;
        debuginfo_eip(ret_addr, &info);

        cprintf("  ebp %08x  eip %08x  args %08x %08x %08x %08x %08x\n"
                "         %s:%d: %.*s+%u\n",
                ebp,
                ret_addr,
                arg0,
                arg1,
                arg2,
                arg3,
                arg4,
                info.eip_file,
                info.eip_line,
                info.eip_fn_namelen,
                info.eip_fn_name,
                ret_addr - info.eip_fn_addr);

        ebp = (uint32_t *)old_ebp;
    }

	return 0;
}

static uint32_t hex2dec(const char *hex)
{
	uint32_t result = 0;

	char xdig;
	while ((xdig = *hex++)) {
		uint32_t dig;

		// Just ignore invalid hex char.
		if (xdig >= '0' && xdig <= '9')
			dig = xdig - '0';
		else if (xdig >= 'a' && xdig <= 'f')
			dig = xdig - 'a' + 10;
		else if (xdig >= 'A' && xdig <= 'F')
			dig = xdig - 'A' + 10;
		else
			continue;
		
		result = (result << 4) | dig;
	}

	return result;
}

static uint32_t string2va(const char *str)
{
	assert(*str == '0');
	str++; // Skip '0'.

	assert(*str == 'x' || *str == 'X');
	str++; // Skip 'x' | 'X'.

	return hex2dec(str);
}

static void showmap(uintptr_t va)
{
	pte_t *pte;
	struct Page *page = page_lookup(kern_pgdir, (void *)va, &pte);

	if (page)
		cprintf("va: 0x%08x, pa: 0x%08x, perm: U(%d), W(%d).\n",
			va,
			page2pa(page),
			!!(*pte & PTE_U),
			!!(*pte & PTE_W));
	else
		cprintf("va: 0x%08x: no map yet.\n", va);
}

int mon_showmap(int argc, char **argv, struct Trapframe *tf)
{
	if (argc == 2) {
		uintptr_t va = string2va(argv[1]);
		
		showmap(va);
	} else if (argc == 3) {
		uintptr_t va_s = string2va(argv[1]);
		uintptr_t va_e = string2va(argv[2]);
		
		assert(va_s < va_e);
		while (va_s <= va_e) {
			showmap(va_s);
			va_s += PGSIZE;
		}
	} else {
		cprintf("You must enter one virtual address to get a physical page or two addresses to form a range!\n");
	}

	return 0;
}

static void showpage(struct Page *page, uint32_t sa /* starting address, either phys or virt */)
{
	if (!page) {
		cprintf("Page is not available.\n");
		return;
	}

	char *pbase = page2kva(page);
	char *pend = pbase + PGSIZE;
	while (pbase < pend) {
		cprintf("%08x:  ", sa);

		int i;
		for (i = 0; i < 16; ++i)
			cprintf("%02x ", (uint8_t)pbase[i]);

		cprintf("\n");

		pbase += 16;
		sa += 16;
	}
}

int mon_showpp(int argc, char **argv, struct Trapframe *tf)
{
	if (argc == 2) {
		uintptr_t pa = ROUNDDOWN(string2va(argv[1]), PGSIZE);

		struct Page *page = pa2page(pa);

		showpage(page, pa);
	}

	return 0;
}

int mon_showvp(int argc, char **argv, struct Trapframe *tf)
{
	if (argc == 2) {
		uintptr_t va = ROUNDDOWN(string2va(argv[1]), PGSIZE);

		pte_t *pte;
		struct Page *page = page_lookup(kern_pgdir, (void *)va, &pte);

		showpage(page, va);
	}

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

// return EIP of caller.
// does not work if inlined.
// putting at the end of the file seems to prevent inlining.
unsigned
read_eip()
{
	uint32_t callerpc;
	__asm __volatile("movl 4(%%ebp), %0" : "=r" (callerpc));
	return callerpc;
}
