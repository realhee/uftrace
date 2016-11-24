#include <string.h>
#include <sys/mman.h>
#include <link.h>
#include <regex.h>

/* This should be defined before #include "utils.h" */
#define PR_FMT     "mcount"
#define PR_DOMAIN  DBG_MCOUNT

#include "utils/symbol.h"
#include "utils/filter.h"

#define PAGE_SIZE  4096
#define PAGE_MASK  (PAGE_SIZE - 1)

/* target profile function it needs to call */
extern void __fentry__(void);

struct arch_dynamic_info {
	struct arch_dynamic_info *next;
	char *mod_name;
	unsigned long addr;
	unsigned long size;
	unsigned long trampoline;
};

static struct arch_dynamic_info *adinfo;

/* callback for dl_iterate_phdr() */
static int find_dynamic_module(struct dl_phdr_info *info, size_t sz, void *data)
{
	const char *name = info->dlpi_name;
	struct arch_dynamic_info *adi;
	unsigned i;

	if ((data == NULL && name[0] == '\0') || strstr(name, data)) {
		adi = xmalloc(sizeof(*adi));
		adi->mod_name = xstrdup(name);

		for (i = 0; i < info->dlpi_phnum; i++) {
			if (info->dlpi_phdr[i].p_type != PT_LOAD)
				continue;

			if (!(info->dlpi_phdr[i].p_flags & PF_X))
				continue;

			/* find address and size of code segment */
			adi->addr = info->dlpi_phdr[i].p_vaddr + info->dlpi_addr;
			adi->size = info->dlpi_phdr[i].p_memsz;
			break;
		}
		adi->next = adinfo;
		adinfo = adi;

		return 1;
	}

	return 0;
}

static void setup_fentry_trampoline(struct arch_dynamic_info *adi)
{
	unsigned char trampoline[] = { 0xff, 0x25, 0x02, 0x00, 0x00, 0x00, 0xcc, 0xcc };
	unsigned long fentry_addr = (unsigned long)__fentry__;

	/* find unused 16-byte at the end of the code segment */
	adi->trampoline = ALIGN(adi->addr + adi->size, PAGE_SIZE) - 16;

	if (unlikely(adi->trampoline < adi->addr + adi->size)) {
		adi->trampoline += 16;
		adi->size += PAGE_SIZE;

		pr_dbg2("adding a page for fentry trampoline at %#lx\n",
			adi->trampoline);

		mmap((void *)adi->trampoline, PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}

	if (mprotect((void *)adi->addr, adi->size, PROT_READ | PROT_WRITE))
		pr_err("cannot setup trampoline due to protection");

	/* jmpq  *0x2(%rip)     # <fentry_addr> */
	memcpy((void *)adi->trampoline, trampoline, sizeof(trampoline));
	memcpy((void *)adi->trampoline + sizeof(trampoline),
	       &fentry_addr, sizeof(fentry_addr));
}

static void cleanup_fentry_trampoline(struct arch_dynamic_info *adi)
{
	if (mprotect((void *)adi->addr, adi->size, PROT_EXEC))
		pr_err("cannot restore trampoline due to protection");
}

static unsigned long get_target_addr(unsigned long addr)
{
	struct arch_dynamic_info *adi = adinfo;

	while (adi) {
		if (adi->addr <= addr && addr < adi->addr + adi->size)
			return adi->trampoline - (addr + 5);

		adi = adi->next;
	}
	return 0;
}

static void prepare_dynamic_update(void)
{
	struct arch_dynamic_info *adi;

	dl_iterate_phdr(find_dynamic_module, NULL);

	adi = adinfo;
	while (adi) {
		setup_fentry_trampoline(adi);
		adi = adi->next;
	}
}

static int update_sym_dynamic(struct sym *sym)
{
	unsigned char nop[] = { 0x67, 0x0f, 0x1f, 0x04, 0x00 };
	unsigned char *insn = (void *)sym->addr;
	unsigned int target_addr;

	target_addr = get_target_addr(sym->addr);
	if (target_addr == 0)
		return 0;

	/* only support calls to __fentry__ at the beginning */
	if (memcmp(insn, nop, sizeof(nop)))
		return 0;

	/* make a "call" insn with 4-byte offset */
	insn[0] = 0xe8;
	/* hopefully we're not patching 'memcpy' itself */
	memcpy(&insn[1], &target_addr, sizeof(target_addr));

	pr_dbg3("update function '%s' dynamically to call __fentry__\n",
		sym->name);

	return 0;
}

static int do_dynamic_update(struct symtabs *symtabs, char *patch_funcs)
{
	char *str;
	char *pos, *name;
	struct symtab *symtab = &symtabs->symtab;

	if (patch_funcs == NULL)
		return 0;

	pos = str = strdup(patch_funcs);
	if (str == NULL)
		return 0;

	name = strtok(pos, ";");
	while (name) {
		bool is_regex;
		regex_t re;
		unsigned i;
		struct sym *sym;

		is_regex = strpbrk(name, REGEX_CHARS);
		if (is_regex) {
			if (regcomp(&re, name, REG_NOSUB | REG_EXTENDED)) {
				pr_dbg("regex pattern failed: %s\n", name);
				return -1;
			}
		}

		for (i = 0; i < symtab->nr_sym; i++) {
			sym = &symtab->sym[i];

			if ((is_regex && regexec(&re, sym->name, 0, NULL, 0)) ||
			    (!is_regex && strcmp(name, sym->name)))
				continue;

			if (update_sym_dynamic(sym) < 0)
				return -1;
		}

		name = strtok(NULL, ";");
	}

	free(str);
	return 0;
}

static void finish_dynamic_update(void)
{
	struct arch_dynamic_info *adi, *tmp;

	adi = adinfo;
	while (adi) {
		tmp = adi->next;

		cleanup_fentry_trampoline(adi);
		free(adi->mod_name);
		free(adi);

		adi = tmp;
	}
}

int mcount_arch_dynamic_update(struct symtabs *symtabs,
			       char *patch_funcs)
{
	prepare_dynamic_update();

	if (do_dynamic_update(symtabs, patch_funcs) < 0)
		return -1;

	finish_dynamic_update();
	return 0;
}
