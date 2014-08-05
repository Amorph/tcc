/*
*  TCC - Tiny C Compiler
*
*  Copyright (c) 2001-2004 Fabrice Bellard
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "tcc.h"

/********************************************************/
/* global variables */

/* use GNU C extensions */
ST_DATA int gnu_ext = 1;

/* use TinyCC extensions */
ST_DATA int tcc_ext = 1;

/* XXX: get rid of this ASAP */
//ST_DATA struct TCCState *tcc_state;

/********************************************************/

#ifdef ONE_SOURCE
#include "tccpp.c"
#include "tccgen.c"
#include "tccelf.c"
#include "tccrun.c"
#ifdef TCC_TARGET_I386
#include "i386-gen.c"
#endif
#ifdef TCC_TARGET_ARM
#include "arm-gen.c"
#endif
#ifdef TCC_TARGET_C67
#include "c67-gen.c"
#endif
#ifdef TCC_TARGET_X86_64
#include "x86_64-gen.c"
#endif
#ifdef CONFIG_TCC_ASM
#include "tccasm.c"
#if defined TCC_TARGET_I386 || defined TCC_TARGET_X86_64
#include "i386-asm.c"
#endif
#endif
#ifdef TCC_TARGET_COFF
#include "tcccoff.c"
#endif
#ifdef TCC_TARGET_PE
#include "tccpe.c"
#endif
#endif /* ONE_SOURCE */
/********************************************************/
#ifndef CONFIG_TCC_ASM
ST_FUNC void asm_instr(TCCState* tcc_state)
{
	tcc_error(tcc_state, "inline asm() not supported");
}
ST_FUNC void asm_global_instr(TCCState *tcc_state)
{
	tcc_error(tcc_state, "inline asm() not supported");
}
#endif

/********************************************************/
#ifdef _WIN32
static char *normalize_slashes(char *path)
{
	char *p;
	for (p = path; *p; ++p)
		if (*p == '\\')
			*p = '/';
	return path;
}

static HMODULE tcc_module;

/* on win32, we suppose the lib and includes are at the location of 'tcc.exe' */
static void tcc_set_lib_path_w32(TCCState *s)
{
	char path[1024], *p;
	GetModuleFileNameA(tcc_module, path, sizeof path);
	p = tcc_basename(normalize_slashes(strlwr(path)));
	if (p - 5 > path && 0 == strncmp(p - 5, "/bin/", 5))
		p -= 5;
	else if (p > path)
		p--;
	*p = 0;
	tcc_set_lib_path(s, path);
}

#ifdef TCC_TARGET_PE
static void tcc_add_systemdir(TCCState *s)
{
	char buf[1000];
	GetSystemDirectory(buf, sizeof buf);
	tcc_add_library_path(s, normalize_slashes(buf));
}
#endif

#ifndef CONFIG_TCC_STATIC
void dlclose(void *p)
{
	FreeLibrary((HMODULE)p);
}
#endif

#ifdef LIBTCC_AS_DLL
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved)
{
	if (DLL_PROCESS_ATTACH == dwReason)
		tcc_module = hDll;
	return TRUE;
}
#endif
#endif

/********************************************************/
/* copy a string and truncate it. */
PUB_FUNC char *pstrcpy(char *buf, int buf_size, const char *s)
{
	char *q, *q_end;
	int c;

	if (buf_size > 0) {
		q = buf;
		q_end = buf + buf_size - 1;
		while (q < q_end) {
			c = *s++;
			if (c == '\0')
				break;
			*q++ = c;
		}
		*q = '\0';
	}
	return buf;
}

/* strcat and truncate. */
PUB_FUNC char *pstrcat(char *buf, int buf_size, const char *s)
{
	int len;
	len = strlen(buf);
	if (len < buf_size)
		pstrcpy(buf + len, buf_size - len, s);
	return buf;
}

PUB_FUNC char *pstrncpy(char *out, const char *in, size_t num)
{
	memcpy(out, in, num);
	out[num] = '\0';
	return out;
}

/* extract the basename of a file */
PUB_FUNC char *tcc_basename(const char *name)
{
	char *p = strchr(name, 0);
	while (p > name && !IS_DIRSEP(p[-1]))
		--p;
	return p;
}

/* extract extension part of a file
*
* (if no extension, return pointer to end-of-string)
*/
PUB_FUNC char *tcc_fileextension(const char *name)
{
	char *b = tcc_basename(name);
	char *e = strrchr(b, '.');
	return e ? e : strchr(b, 0);
}

/********************************************************/
/* memory management */

#undef free
#undef malloc
#undef realloc

#ifdef MEM_DEBUG
ST_DATA int mem_cur_size;
ST_DATA int mem_max_size;
unsigned malloc_usable_size(void*);
#endif

PUB_FUNC void tcc_free(TCCState* tcc_state, void *ptr)
{
#ifdef MEM_DEBUG
	mem_cur_size -= malloc_usable_size(ptr);
#endif
	free(ptr);
}

PUB_FUNC void *tcc_malloc(TCCState* tcc_state, unsigned long size)
{
	void *ptr;
	ptr = malloc(size);
	if (!ptr && size)
		tcc_error(tcc_state, "memory full (malloc)");
#ifdef MEM_DEBUG
	mem_cur_size += malloc_usable_size(ptr);
	if (mem_cur_size > mem_max_size)
		mem_max_size = mem_cur_size;
#endif
	return ptr;
}

PUB_FUNC void *tcc_mallocz(TCCState* tcc_state, unsigned long size)
{
	void *ptr;
	ptr = tcc_malloc(tcc_state, size);
	memset(ptr, 0, size);
	return ptr;
}

PUB_FUNC void *tcc_realloc(TCCState* tcc_state, void *ptr, unsigned long size)
{
	void *ptr1;
#ifdef MEM_DEBUG
	mem_cur_size -= malloc_usable_size(ptr);
#endif
	ptr1 = realloc(ptr, size);
	if (!ptr1 && size)
		tcc_error(tcc_state, "memory full (realloc)");
#ifdef MEM_DEBUG
	/* NOTE: count not correct if alloc error, but not critical */
	mem_cur_size += malloc_usable_size(ptr1);
	if (mem_cur_size > mem_max_size)
		mem_max_size = mem_cur_size;
#endif
	return ptr1;
}

PUB_FUNC char *tcc_strdup(TCCState *tcc_state, const char *str)
{
	char *ptr;
	ptr = tcc_malloc(tcc_state, strlen(str) + 1);
	strcpy(ptr, str);
	return ptr;
}

PUB_FUNC void tcc_memstats(TCCState *tcc_state)
{
#ifdef MEM_DEBUG
	printf("memory: %d bytes, max = %d bytes\n", mem_cur_size, mem_max_size);
#endif
}

#define free(tcc_state, p) use_tcc_free(tcc_state, p)
#define malloc(tcc_state, s) use_tcc_malloc(tcc_state, s)
#define realloc(tcc_state, p, s) use_tcc_realloc(tcc_state, p, s)

/********************************************************/
/* dynarrays */

ST_FUNC void dynarray_add(TCCState *tcc_state, void ***ptab, int *nb_ptr, void *data)
{
	int nb, nb_alloc;
	void **pp;

	nb = *nb_ptr;
	pp = *ptab;
	/* every power of two we double array size */
	if ((nb & (nb - 1)) == 0) {
		if (!nb)
			nb_alloc = 1;
		else
			nb_alloc = nb * 2;
		pp = tcc_realloc(tcc_state, pp, nb_alloc * sizeof(void *));
		*ptab = pp;
	}
	pp[nb++] = data;
	*nb_ptr = nb;
}

ST_FUNC void dynarray_reset(TCCState *tcc_state, void *pp, int *n)
{
	void **p;
	for (p = *(void***)pp; *n; ++p, --*n)
		if (*p)
			tcc_free(tcc_state, *p);
	tcc_free(tcc_state, *(void**)pp);
	*(void**)pp = NULL;
}

static void tcc_split_path(TCCState *s, void ***p_ary, int *p_nb_ary, const char *in)
{
	const char *p;
	do {
		int c;
		CString str;

		cstr_new(&str);
		for (p = in; c = *p, c != '\0' && c != PATHSEP; ++p) {
			if (c == '{' && p[1] && p[2] == '}') {
				c = p[1], p += 2;
				if (c == 'B')
					cstr_cat(s, &str, s->tcc_lib_path);
			}
			else {
				cstr_ccat(s, &str, c);
			}
		}
		cstr_ccat(s, &str, '\0');
		dynarray_add(s, p_ary, p_nb_ary, str.data);
		in = p + 1;
	} while (*p);
}

/********************************************************/

ST_FUNC Section *new_section(TCCState *s1, const char *name, int sh_type, int sh_flags)
{
	Section *sec;

	sec = tcc_mallocz(s1, sizeof(Section) + strlen(name));
	strcpy(sec->name, name);
	sec->sh_type = sh_type;
	sec->sh_flags = sh_flags;
	switch (sh_type) {
	case SHT_HASH:
	case SHT_REL:
	case SHT_RELA:
	case SHT_DYNSYM:
	case SHT_SYMTAB:
	case SHT_DYNAMIC:
		sec->sh_addralign = 4;
		break;
	case SHT_STRTAB:
		sec->sh_addralign = 1;
		break;
	default:
		sec->sh_addralign = 32; /* default conservative alignment */
		break;
	}

	if (sh_flags & SHF_PRIVATE) {
		dynarray_add(s1, (void ***)&s1->priv_sections, &s1->nb_priv_sections, sec);
	}
	else {
		sec->sh_num = s1->nb_sections;
		dynarray_add(s1, (void ***)&s1->sections, &s1->nb_sections, sec);
	}

	return sec;
}

static void free_section(TCCState *tcc_state, Section *s)
{
	tcc_free(tcc_state, s->data);
}

/* realloc section and set its content to zero */
ST_FUNC void section_realloc(TCCState *tcc_state, Section *sec, unsigned long new_size)
{
	unsigned long size;
	unsigned char *data;

	size = sec->data_allocated;
	if (size == 0)
		size = 1;
	while (size < new_size)
		size = size * 2;
	data = tcc_realloc(tcc_state, sec->data, size);
	memset(data + sec->data_allocated, 0, size - sec->data_allocated);
	sec->data = data;
	sec->data_allocated = size;
}

/* reserve at least 'size' bytes in section 'sec' from
sec->data_offset. */
ST_FUNC void *section_ptr_add(TCCState *tcc_state, Section *sec, unsigned long size)
{
	unsigned long offset, offset1;

	offset = sec->data_offset;
	offset1 = offset + size;
	if (offset1 > sec->data_allocated)
		section_realloc(tcc_state, sec, offset1);
	sec->data_offset = offset1;
	return sec->data + offset;
}

/* reserve at least 'size' bytes from section start */
ST_FUNC void section_reserve(TCCState *tcc_state, Section *sec, unsigned long size)
{
	if (size > sec->data_allocated)
		section_realloc(tcc_state, sec, size);
	if (size > sec->data_offset)
		sec->data_offset = size;
}

/* return a reference to a section, and create it if it does not
exists */
ST_FUNC Section *find_section(TCCState *s1, const char *name)
{
	Section *sec;
	int i;
	for (i = 1; i < s1->nb_sections; i++) {
		sec = s1->sections[i];
		if (!strcmp(name, sec->name))
			return sec;
	}
	/* sections are created as PROGBITS */
	return new_section(s1, name, SHT_PROGBITS, SHF_ALLOC);
}

/* update sym->c so that it points to an external symbol in section
'section' with value 'value' */
ST_FUNC void put_extern_sym2(TCCState *tcc_state, Sym *sym, Section *section,
	addr_t value, unsigned long size,
	int can_add_underscore)
{
	int sym_type, sym_bind, sh_num, info, other;
	ElfW(Sym) *esym;
	const char *name;
	char buf1[256];

	if (section == NULL)
		sh_num = SHN_UNDEF;
	else if (section == SECTION_ABS)
		sh_num = SHN_ABS;
	else
		sh_num = section->sh_num;

	if ((sym->type.t & VT_BTYPE) == VT_FUNC) {
		sym_type = STT_FUNC;
	}
	else if ((sym->type.t & VT_BTYPE) == VT_VOID) {
		sym_type = STT_NOTYPE;
	}
	else {
		sym_type = STT_OBJECT;
	}

	if (sym->type.t & VT_STATIC)
		sym_bind = STB_LOCAL;
	else {
		if (sym->type.t & VT_WEAK)
			sym_bind = STB_WEAK;
		else
			sym_bind = STB_GLOBAL;
	}

	if (!sym->c) {
		name = get_tok_str(tcc_state, sym->v, NULL);
#ifdef CONFIG_TCC_BCHECK
		if (tcc_state->do_bounds_check) {
			char buf[32];

			/* XXX: avoid doing that for statics ? */
			/* if bound checking is activated, we change some function
			names by adding the "__bound" prefix */
			switch (sym->v) {
#ifdef TCC_TARGET_PE
				/* XXX: we rely only on malloc hooks */
			case TOK_malloc:
			case TOK_free:
			case TOK_realloc:
			case TOK_memalign:
			case TOK_calloc:
#endif
			case TOK_memcpy:
			case TOK_memmove:
			case TOK_memset:
			case TOK_strlen:
			case TOK_strcpy:
#if defined TCC_TARGET_I386 || defined TCC_TARGET_X86_64
			case TOK_alloca:
#endif
				strcpy(buf, "__bound_");
				strcat(buf, name);
				name = buf;
				break;
			}
		}
#endif
		other = 0;

#ifdef TCC_TARGET_PE
		if (sym->type.t & VT_EXPORT)
			other |= ST_PE_EXPORT;
		if (sym_type == STT_FUNC && sym->type.ref) {
			Sym *ref = sym->type.ref;
			if (ref->a.func_export)
				other |= ST_PE_EXPORT;
			if (ref->a.func_call == FUNC_STDCALL && can_add_underscore) {
				sprintf(buf1, "_%s@%d", name, ref->a.func_args * PTR_SIZE);
				name = buf1;
				other |= ST_PE_STDCALL;
				can_add_underscore = 0;
			}
		}
		else {
			if (find_elf_sym(tcc_state->dynsymtab_section, name))
				other |= ST_PE_IMPORT;
			if (sym->type.t & VT_IMPORT)
				other |= ST_PE_IMPORT;
		}
#else
		if (!(sym->type.t & VT_STATIC))
			other = (sym->type.t & VT_VIS_MASK) >> VT_VIS_SHIFT;
#endif
		if (tcc_state->leading_underscore && can_add_underscore) {
			buf1[0] = '_';
			pstrcpy(buf1 + 1, sizeof(buf1) - 1, name);
			name = buf1;
		}
		if (sym->asm_label) {
			name = sym->asm_label;
		}
		info = ELFW(ST_INFO)(sym_bind, sym_type);
		sym->c = add_elf_sym(tcc_state, tcc_state->symtab_section, value, size, info, other, sh_num, name);
	}
	else {
		esym = &((ElfW(Sym) *)tcc_state->symtab_section->data)[sym->c];
		esym->st_value = value;
		esym->st_size = size;
		esym->st_shndx = sh_num;
	}
}

ST_FUNC void put_extern_sym(TCCState *tcc_state, Sym *sym, Section *section,
	addr_t value, unsigned long size)
{
	put_extern_sym2(tcc_state, sym, section, value, size, 1);
}

/* add a new relocation entry to symbol 'sym' in section 's' */
ST_FUNC void greloc(TCCState *tcc_state, Section *s, Sym *sym, unsigned long offset, int type)
{
	int c = 0;
	if (sym) {
		if (0 == sym->c)
			put_extern_sym(tcc_state, sym, NULL, 0, 0);
		c = sym->c;
	}
	/* now we can add ELF relocation info */
	put_elf_reloc(tcc_state, tcc_state->symtab_section, s, offset, type, c);
}

/********************************************************/

static void strcat_vprintf(char *buf, int buf_size, const char *fmt, va_list ap)
{
	int len;
	len = strlen(buf);
	vsnprintf(buf + len, buf_size - len, fmt, ap);
}

static void strcat_printf(char *buf, int buf_size, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	strcat_vprintf(buf, buf_size, fmt, ap);
	va_end(ap);
}

static void error1(TCCState *s1, int is_warning, const char *fmt, va_list ap)
{
	char buf[2048];
	BufferedFile **pf, *f;

	buf[0] = '\0';
	/* use upper file if inline ":asm:" or token ":paste:" */
	for (f = s1->file; f && f->filename[0] == ':'; f = f->prev)
		;
	if (f) {
		for (pf = s1->include_stack; pf < s1->include_stack_ptr; pf++)
			strcat_printf(buf, sizeof(buf), "In file included from %s:%d:\n",
			(*pf)->filename, (*pf)->line_num);
		if (f->line_num > 0) {
			strcat_printf(buf, sizeof(buf), "%s:%d: ",
				f->filename, f->line_num);
		}
		else {
			strcat_printf(buf, sizeof(buf), "%s: ",
				f->filename);
		}
	}
	else {
		strcat_printf(buf, sizeof(buf), "tcc: ");
	}
	if (is_warning)
		strcat_printf(buf, sizeof(buf), "warning: ");
	else
		strcat_printf(buf, sizeof(buf), "error: ");
	strcat_vprintf(buf, sizeof(buf), fmt, ap);

	if (!s1->error_func) {
		/* default case: stderr */
		fprintf(stderr, "%s\n", buf);
	}
	else {
		s1->error_func(s1->error_opaque, buf);
	}
	if (!is_warning || s1->warn_error)
		s1->nb_errors++;
}

LIBTCCAPI void tcc_set_error_func(TCCState *s, void *error_opaque,
	void(*error_func)(void *opaque, const char *msg))
{
	s->error_opaque = error_opaque;
	s->error_func = error_func;
}

/* error without aborting current compilation */
PUB_FUNC void tcc_error_noabort(TCCState *tcc_state, const char *fmt, ...)
{
	TCCState *s1 = tcc_state;
	va_list ap;

	va_start(ap, fmt);
	error1(s1, 0, fmt, ap);
	va_end(ap);
}

PUB_FUNC void tcc_error(TCCState *tcc_state, const char *fmt, ...)
{
	TCCState *s1 = tcc_state;
	va_list ap;

	va_start(ap, fmt);
	error1(s1, 0, fmt, ap);
	va_end(ap);
	/* better than nothing: in some cases, we accept to handle errors */
	if (s1->error_set_jmp_enabled) {
		longjmp(s1->error_jmp_buf, 1);
	}
	else {
		/* XXX: eliminate this someday */
		exit(1);
	}
}

PUB_FUNC void tcc_warning(TCCState *tcc_state, const char *fmt, ...)
{
	TCCState *s1 = tcc_state;
	va_list ap;

	if (s1->warn_none)
		return;

	va_start(ap, fmt);
	error1(s1, 1, fmt, ap);
	va_end(ap);
}

/********************************************************/
/* I/O layer */

ST_FUNC void tcc_open_bf(TCCState *s1, const char *filename, int initlen)
{
	BufferedFile *bf;
	int buflen = initlen ? initlen : IO_BUF_SIZE;

	bf = tcc_malloc(s1, sizeof(BufferedFile) + buflen);
	bf->buf_ptr = bf->buffer;
	bf->buf_end = bf->buffer + initlen;
	bf->buf_end[0] = CH_EOB; /* put eob symbol */
	pstrcpy(bf->filename, sizeof(bf->filename), filename);
#ifdef _WIN32
	normalize_slashes(bf->filename);
#endif
	bf->line_num = 1;
	bf->ifndef_macro = 0;
	bf->ifdef_stack_ptr = s1->ifdef_stack_ptr;
	bf->fd = -1;
	bf->prev = s1->file;
	s1->file = bf;
}

ST_FUNC void tcc_close(TCCState *tcc_state)
{
	BufferedFile *bf = tcc_state->file;
	if (bf->fd > 0) {
		close(bf->fd);
		tcc_state->total_lines += bf->line_num;
	}
	tcc_state->file = bf->prev;
	tcc_free(tcc_state, bf);
}

ST_FUNC int tcc_open(TCCState *tcc_state, const char *filename)
{
	int fd;
	if (strcmp(filename, "-") == 0)
		fd = 0, filename = "stdin";
	else
		fd = open(filename, O_RDONLY | O_BINARY);
	if ((tcc_state->verbose == 2 && fd >= 0) || tcc_state->verbose == 3)
		printf("%s %*s%s\n", fd < 0 ? "nf" : "->",
		(int)(tcc_state->include_stack_ptr - tcc_state->include_stack), "", filename);
	if (fd < 0)
		return -1;

	tcc_open_bf(tcc_state, filename, 0);
	tcc_state->file->fd = fd;
	return fd;
}

/* compile the C file opened in 'file'. Return non zero if errors. */
static int tcc_compile(TCCState *tcc_state)
{
	Sym *define_start;
	SValue *pvtop;
	char buf[512];
	volatile int section_sym;

#ifdef INC_DEBUG
	printf("%s: **** new file\n", file->filename);
#endif
	preprocess_init(tcc_state);

	tcc_state->cur_text_section = NULL;
	tcc_state->funcname = "";
	tcc_state->anon_sym = SYM_FIRST_ANOM;

	/* file info: full path + filename */
	section_sym = 0; /* avoid warning */
	if (tcc_state->do_debug) {
		section_sym = put_elf_sym(tcc_state, tcc_state->symtab_section, 0, 0,
			ELFW(ST_INFO)(STB_LOCAL, STT_SECTION), 0,
			tcc_state->text_section->sh_num, NULL);
		getcwd(buf, sizeof(buf));
#ifdef _WIN32
		normalize_slashes(buf);
#endif
		pstrcat(buf, sizeof(buf), "/");
		put_stabs_r(tcc_state, buf, N_SO, 0, 0,
			tcc_state->text_section->data_offset, tcc_state->text_section, section_sym);
		put_stabs_r(tcc_state, tcc_state->file->filename, N_SO, 0, 0,
			tcc_state->text_section->data_offset, tcc_state->text_section, section_sym);
	}
	/* an elf symbol of type STT_FILE must be put so that STB_LOCAL
	symbols can be safely used */
	put_elf_sym(tcc_state, tcc_state->symtab_section, 0, 0,
		ELFW(ST_INFO)(STB_LOCAL, STT_FILE), 0,
		SHN_ABS, tcc_state->file->filename);

	/* define some often used types */
	tcc_state->int_type.t = VT_INT;

	tcc_state->char_pointer_type.t = VT_BYTE;
	mk_pointer(tcc_state, &tcc_state->char_pointer_type);

#if PTR_SIZE == 4
	tcc_state->size_type.t = VT_INT;
#else
	tcc_state->size_type.t = VT_LLONG;
#endif

	tcc_state->func_old_type.t = VT_FUNC;
	tcc_state->func_old_type.ref = sym_push(tcc_state, SYM_FIELD, &tcc_state->int_type, FUNC_CDECL, FUNC_OLD);
#ifdef TCC_TARGET_ARM
	arm_init(tcc_state);
#endif

#if 0
	/* define 'void *alloca(unsigned int)' builtin function */
	{
		Sym *s1;

		p = anon_sym++;
		sym = sym_push(s1, p, mk_pointer(tcc_state, VT_VOID), FUNC_CDECL, FUNC_NEW);
		s1 = sym_push(s1, SYM_FIELD, VT_UNSIGNED | VT_INT, 0, 0);
		s1->next = NULL;
		sym->next = tcc_state;
		sym_push(tcc_state, TOK_alloca, VT_FUNC | (p << VT_STRUCT_SHIFT), VT_CONST, 0);
	}
#endif

	define_start = tcc_state->define_stack;

	if (setjmp(tcc_state->error_jmp_buf) == 0) {
		tcc_state->nb_errors = 0;
		tcc_state->error_set_jmp_enabled = 1;

		tcc_state->ch = tcc_state->file->buf_ptr[0];
		tcc_state->tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
		tcc_state->parse_flags = PARSE_FLAG_PREPROCESS | PARSE_FLAG_TOK_NUM;
		pvtop = tcc_state->vtop;
		next(tcc_state);
		decl(tcc_state, VT_CONST);
		if (tcc_state->tok != TOK_EOF)
			expect(tcc_state, "declaration");
		if (pvtop != tcc_state->vtop)
			tcc_warning(tcc_state, "internal compiler error: vstack leak? (%d)", tcc_state->vtop - pvtop);

		/* end of translation unit info */
		if (tcc_state->do_debug) {
			put_stabs_r(tcc_state, NULL, N_SO, 0, 0,
				tcc_state->text_section->data_offset, tcc_state->text_section, section_sym);
		}
	}

	tcc_state->error_set_jmp_enabled = 0;

	/* reset define stack, but leave -Dsymbols (may be incorrect if
	they are undefined) */
	free_defines(tcc_state, define_start);

	gen_inline_functions(tcc_state);

	sym_pop(tcc_state, &tcc_state->global_stack, NULL);
	sym_pop(tcc_state, &tcc_state->local_stack, NULL);

	return tcc_state->nb_errors != 0 ? -1 : 0;
}

LIBTCCAPI int tcc_compile_string(TCCState *tcc_state, const char *str)
{
	int len, ret;
	len = strlen(str);

	tcc_open_bf(tcc_state, "<string>", len);
	memcpy(tcc_state->file->buffer, str, len);
	ret = tcc_compile(tcc_state);
	tcc_close(tcc_state);
	return ret;
}

/* define a preprocessor symbol. A value can also be provided with the '=' operator */
LIBTCCAPI void tcc_define_symbol(TCCState *tcc_state, const char *sym, const char *value)
{
	int len1, len2;
	/* default value */
	if (!value)
		value = "1";
	len1 = strlen(sym);
	len2 = strlen(value);

	/* init file structure */
	tcc_open_bf(tcc_state, "<define>", len1 + len2 + 1);
	memcpy(tcc_state->file->buffer, sym, len1);
	tcc_state->file->buffer[len1] = ' ';
	memcpy(tcc_state->file->buffer + len1 + 1, value, len2);

	/* parse with define parser */
	tcc_state->ch = tcc_state->file->buf_ptr[0];
	next_nomacro(tcc_state);
	parse_define(tcc_state);

	tcc_close(tcc_state);
}

/* undefine a preprocessor symbol */
LIBTCCAPI void tcc_undefine_symbol(TCCState *tcc_state, const char *sym)
{
	TokenSym *ts;
	Sym *s;
	ts = tok_alloc(tcc_state, sym, strlen(sym));
	s = define_find(ts->tok);
	/* undefine symbol by putting an invalid name */
	if (s)
		define_undef(s);
}

/* cleanup all static data used during compilation */
static void tcc_cleanup(TCCState *tcc_state)
{
	int i, n;
	if (NULL == tcc_state)
		return;
	tcc_state = NULL;

	/* free -D defines */
	free_defines(tcc_state, NULL);

	/* free tokens */
	n = tcc_state->tok_ident - TOK_IDENT;
	for (i = 0; i < n; i++)
		tcc_free(tcc_state, tcc_state->table_ident[i]);
	tcc_free(tcc_state, tcc_state->table_ident);

	/* free sym_pools */
	dynarray_reset(tcc_state, &tcc_state->sym_pools, &tcc_state->nb_sym_pools);
	/* string buffer */
	cstr_free(tcc_state, &tcc_state->tokcstr);
	/* reset symbol stack */
	tcc_state->sym_free_first = NULL;
	/* cleanup from error/setjmp */
	tcc_state->macro_ptr = NULL;
}

LIBTCCAPI TCCState *tcc_new(void)
{
	TCCState *s, *tcc_state;
	char buffer[100];
	int a, b, c;

	//tcc_cleanup();
	//TODO make manual allocation for TCCState
	tcc_state = s = tcc_mallocz(0, sizeof(TCCState));
	if (!s)
		return NULL;
#ifdef _WIN32
	tcc_set_lib_path_w32(s);
#else
	tcc_set_lib_path(s, CONFIG_TCCDIR);
#endif
	s->output_type = TCC_OUTPUT_MEMORY;
	preprocess_new(s);
	s->include_stack_ptr = s->include_stack;

	/* we add dummy defines for some special macros to speed up tests
	and to have working defined() */
	define_push(s, TOK___LINE__, MACRO_OBJ, NULL, NULL);
	define_push(s, TOK___FILE__, MACRO_OBJ, NULL, NULL);
	define_push(s, TOK___DATE__, MACRO_OBJ, NULL, NULL);
	define_push(s, TOK___TIME__, MACRO_OBJ, NULL, NULL);

	/* define __TINYC__ 92X  */
	sscanf(TCC_VERSION, "%d.%d.%d", &a, &b, &c);
	sprintf(buffer, "%d", a * 10000 + b * 100 + c);
	tcc_define_symbol(s, "__TINYC__", buffer);

	/* standard defines */
	tcc_define_symbol(s, "__STDC__", NULL);
	tcc_define_symbol(s, "__STDC_VERSION__", "199901L");
	tcc_define_symbol(s, "__STDC_HOSTED__", NULL);

	/* target defines */
#if defined(TCC_TARGET_I386)
	tcc_define_symbol(s, "__i386__", NULL);
	tcc_define_symbol(s, "__i386", NULL);
	tcc_define_symbol(s, "i386", NULL);
#elif defined(TCC_TARGET_X86_64)
	tcc_define_symbol(s, "__x86_64__", NULL);
#elif defined(TCC_TARGET_ARM)
	tcc_define_symbol(s, "__ARM_ARCH_4__", NULL);
	tcc_define_symbol(s, "__arm_elf__", NULL);
	tcc_define_symbol(s, "__arm_elf", NULL);
	tcc_define_symbol(s, "arm_elf", NULL);
	tcc_define_symbol(s, "__arm__", NULL);
	tcc_define_symbol(s, "__arm", NULL);
	tcc_define_symbol(s, "arm", NULL);
	tcc_define_symbol(s, "__APCS_32__", NULL);
	tcc_define_symbol(s, "__ARMEL__", NULL);
#if defined(TCC_ARM_EABI)
	tcc_define_symbol(s, "__ARM_EABI__", NULL);
#endif
#if defined(TCC_ARM_HARDFLOAT)
	s->float_abi = ARM_HARD_FLOAT;
	tcc_define_symbol(s, "__ARM_PCS_VFP", NULL);
#else
	s->float_abi = ARM_SOFTFP_FLOAT;
#endif
#endif

#ifdef TCC_TARGET_PE
	tcc_define_symbol(s, "_WIN32", NULL);
# ifdef TCC_TARGET_X86_64
	tcc_define_symbol(s, "_WIN64", NULL);
# endif
#else
	tcc_define_symbol(s, "__unix__", NULL);
	tcc_define_symbol(s, "__unix", NULL);
	tcc_define_symbol(s, "unix", NULL);
# if defined(__linux)
	tcc_define_symbol(s, "__linux__", NULL);
	tcc_define_symbol(s, "__linux", NULL);
# endif
# if defined(__FreeBSD__)
#  define str(s) #s
	tcc_define_symbol(s, "__FreeBSD__", str(__FreeBSD__));
#  undef str
# endif
# if defined(__FreeBSD_kernel__)
	tcc_define_symbol(s, "__FreeBSD_kernel__", NULL);
# endif
#endif

	/* TinyCC & gcc defines */
#if defined TCC_TARGET_PE && defined TCC_TARGET_X86_64
	tcc_define_symbol(s, "__SIZE_TYPE__", "unsigned long long");
	tcc_define_symbol(s, "__PTRDIFF_TYPE__", "long long");
#else
	tcc_define_symbol(s, "__SIZE_TYPE__", "unsigned long");
	tcc_define_symbol(s, "__PTRDIFF_TYPE__", "long");
#endif

#ifdef TCC_TARGET_PE
	tcc_define_symbol(s, "__WCHAR_TYPE__", "unsigned short");
	tcc_define_symbol(s, "__WINT_TYPE__", "unsigned short");
#else
	tcc_define_symbol(s, "__WCHAR_TYPE__", "int");
	/* wint_t is unsigned int by default, but (signed) int on BSDs
	and unsigned short on windows.  Other OSes might have still
	other conventions, sigh.  */
#if defined(__FreeBSD__) || defined (__FreeBSD_kernel__)
	tcc_define_symbol(s, "__WINT_TYPE__", "int");
#else
	tcc_define_symbol(s, "__WINT_TYPE__", "unsigned int");
#endif
#endif

#ifndef TCC_TARGET_PE
	/* glibc defines */
	tcc_define_symbol(s, "__REDIRECT(name, proto, alias)", "name proto __asm__ (#alias)");
	tcc_define_symbol(s, "__REDIRECT_NTH(name, proto, alias)", "name proto __asm__ (#alias) __THROW");
	/* paths for crt objects */
	tcc_split_path(s, (void ***)&s->crt_paths, &s->nb_crt_paths, CONFIG_TCC_CRTPREFIX);
#endif

	/* no section zero */
	dynarray_add(s, (void ***)&s->sections, &s->nb_sections, NULL);

	/* create standard sections */
	tcc_state->text_section = new_section(s, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
	tcc_state->data_section = new_section(s, ".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
	tcc_state->bss_section = new_section(s, ".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE);

	/* symbols are always generated for linking stage */
	tcc_state->symtab_section = new_symtab(s, ".symtab", SHT_SYMTAB, 0,
		".strtab",
		".hashtab", SHF_PRIVATE);
	tcc_state->strtab_section = tcc_state->symtab_section->link;
	s->symtab = tcc_state->symtab_section;

	/* private symbol table for dynamic symbols */
	s->dynsymtab_section = new_symtab(s, ".dynsymtab", SHT_SYMTAB, SHF_PRIVATE,
		".dynstrtab",
		".dynhashtab", SHF_PRIVATE);
	s->alacarte_link = 1;
	s->nocommon = 1;

#ifdef CHAR_IS_UNSIGNED
	s->char_is_unsigned = 1;
#endif
	/* enable this if you want symbols with leading underscore on windows: */
#if 0 /* def TCC_TARGET_PE */
	s->leading_underscore = 1;
#endif
#ifdef TCC_TARGET_I386
	s->seg_size = 32;
#endif
#ifdef TCC_IS_NATIVE
	s->runtime_main = "main";
#endif
	return s;
}

LIBTCCAPI void tcc_delete(TCCState *s1)
{
	int i;

	tcc_cleanup(s1);

	/* free all sections */
	for (i = 1; i < s1->nb_sections; i++)
		free_section(s1, s1->sections[i]);
	dynarray_reset(s1, &s1->sections, &s1->nb_sections);

	for (i = 0; i < s1->nb_priv_sections; i++)
		free_section(s1, s1->priv_sections[i]);
	dynarray_reset(s1, &s1->priv_sections, &s1->nb_priv_sections);

	/* free any loaded DLLs */
#ifdef TCC_IS_NATIVE
	for (i = 0; i < s1->nb_loaded_dlls; i++) {
		DLLReference *ref = s1->loaded_dlls[i];
		if (ref->handle)
			dlclose(ref->handle);
	}
#endif

	/* free loaded dlls array */
	dynarray_reset(s1, &s1->loaded_dlls, &s1->nb_loaded_dlls);

	/* free library paths */
	dynarray_reset(s1, &s1->library_paths, &s1->nb_library_paths);
	dynarray_reset(s1, &s1->crt_paths, &s1->nb_crt_paths);

	/* free include paths */
	dynarray_reset(s1, &s1->cached_includes, &s1->nb_cached_includes);
	dynarray_reset(s1, &s1->include_paths, &s1->nb_include_paths);
	dynarray_reset(s1, &s1->sysinclude_paths, &s1->nb_sysinclude_paths);

	tcc_free(s1, s1->tcc_lib_path);
	tcc_free(s1, s1->soname);
	tcc_free(s1, s1->rpath);
	tcc_free(s1, s1->init_symbol);
	tcc_free(s1, s1->fini_symbol);
	tcc_free(s1, s1->outfile);
	tcc_free(s1, s1->deps_outfile);
	dynarray_reset(s1, &s1->files, &s1->nb_files);
	dynarray_reset(s1, &s1->target_deps, &s1->nb_target_deps);

#ifdef TCC_IS_NATIVE
# ifdef HAVE_SELINUX
	munmap(s1->write_mem, s1->mem_size);
	munmap(s1->runtime_mem, s1->mem_size);
# else
	tcc_free(s1, s1->runtime_mem);
# endif
#endif

	if (s1->sym_attrs) tcc_free(s1, s1->sym_attrs);

	tcc_free(s1, s1);
}

LIBTCCAPI int tcc_add_include_path(TCCState *s, const char *pathname)
{
	tcc_split_path(s, (void ***)&s->include_paths, &s->nb_include_paths, pathname);
	return 0;
}

LIBTCCAPI int tcc_add_sysinclude_path(TCCState *s, const char *pathname)
{
	tcc_split_path(s, (void ***)&s->sysinclude_paths, &s->nb_sysinclude_paths, pathname);
	return 0;
}

ST_FUNC int tcc_add_file_internal(TCCState *tcc_state, const char *filename, int flags)
{
	const char *ext;
	ElfW(Ehdr) ehdr;
	int fd, ret, size;

	/* find source file type with extension */
	ext = tcc_fileextension(filename);
	if (ext[0])
		ext++;

#ifdef CONFIG_TCC_ASM
	/* if .S file, define __ASSEMBLER__ like gcc does */
	if (!strcmp(ext, "S"))
		tcc_define_symbol(tcc_state, "__ASSEMBLER__", NULL);
#endif

	/* open the file */
	ret = tcc_open(tcc_state, filename);
	if (ret < 0) {
		if (flags & AFF_PRINT_ERROR)
			tcc_error_noabort(tcc_state, "file '%s' not found", filename);
		return ret;
	}

	/* update target deps */
	dynarray_add(tcc_state, (void ***)&tcc_state->target_deps, &tcc_state->nb_target_deps,
		tcc_strdup(tcc_state, filename));

	if (flags & AFF_PREPROCESS) {
		ret = tcc_preprocess(tcc_state);
		goto the_end;
	}

	if (!ext[0] || !PATHCMP(ext, "c")) {
		/* C file assumed */
		ret = tcc_compile(tcc_state);
		goto the_end;
	}

#ifdef CONFIG_TCC_ASM
	if (!strcmp(ext, "S")) {
		/* preprocessed assembler */
		ret = tcc_assemble(tcc_state, 1);
		goto the_end;
	}

	if (!strcmp(ext, "s")) {
		/* non preprocessed assembler */
		ret = tcc_assemble(tcc_state, 0);
		goto the_end;
	}
#endif

	fd = tcc_state->file->fd;
	/* assume executable format: auto guess file type */
	size = read(fd, &ehdr, sizeof(ehdr));
	lseek(fd, 0, SEEK_SET);
	if (size <= 0) {
		tcc_error_noabort(tcc_state, "could not read header");
		goto the_end;
	}

	if (size == sizeof(ehdr) &&
		ehdr.e_ident[0] == ELFMAG0 &&
		ehdr.e_ident[1] == ELFMAG1 &&
		ehdr.e_ident[2] == ELFMAG2 &&
		ehdr.e_ident[3] == ELFMAG3) {

		/* do not display line number if error */
		tcc_state->file->line_num = 0;
		if (ehdr.e_type == ET_REL) {
			ret = tcc_load_object_file(tcc_state, fd, 0);
			goto the_end;

		}
#ifndef TCC_TARGET_PE
		if (ehdr.e_type == ET_DYN) {
			if (tcc_state->output_type == TCC_OUTPUT_MEMORY) {
#ifdef TCC_IS_NATIVE
				void *h;
				h = dlopen(filename, RTLD_GLOBAL | RTLD_LAZY);
				if (h)
#endif
					ret = 0;
			}
			else {
				ret = tcc_load_dll(tcc_state, fd, filename,
					(flags & AFF_REFERENCED_DLL) != 0);
			}
			goto the_end;
		}
#endif
		tcc_error_noabort(tcc_state, "unrecognized ELF file");
		goto the_end;
	}

	if (memcmp((char *)&ehdr, ARMAG, 8) == 0) {
		tcc_state->file->line_num = 0; /* do not display line number if error */
		ret = tcc_load_archive(tcc_state, fd);
		goto the_end;
	}

#ifdef TCC_TARGET_COFF
	if (*(uint16_t *)(&ehdr) == COFF_C67_MAGIC) {
		ret = tcc_load_coff(tcc_state, fd);
		goto the_end;
	}
#endif

#ifdef TCC_TARGET_PE
	ret = pe_load_file(tcc_state, filename, fd);
#else
	/* as GNU ld, consider it is an ld script if not recognized */
	ret = tcc_load_ldscript(tcc_state);
#endif
	if (ret < 0)
		tcc_error_noabort(tcc_state, "unrecognized file type");

the_end:
	tcc_close(tcc_state);
	return ret;
}

LIBTCCAPI int tcc_add_file(TCCState *tcc_state, const char *filename)
{
	if (tcc_state->output_type == TCC_OUTPUT_PREPROCESS)
		return tcc_add_file_internal(tcc_state, filename, AFF_PRINT_ERROR | AFF_PREPROCESS);
	else
		return tcc_add_file_internal(tcc_state, filename, AFF_PRINT_ERROR);
}

LIBTCCAPI int tcc_add_library_path(TCCState *tcc_state, const char *pathname)
{
	tcc_split_path(tcc_state, (void ***)&tcc_state->library_paths, &tcc_state->nb_library_paths, pathname);
	return 0;
}

static int tcc_add_library_internal(TCCState *tcc_state, const char *fmt,
	const char *filename, int flags, char **paths, int nb_paths)
{
	char buf[1024];
	int i;

	for (i = 0; i < nb_paths; i++) {
		snprintf(buf, sizeof(buf), fmt, paths[i], filename);
		if (tcc_add_file_internal(tcc_state, buf, flags) == 0)
			return 0;
	}
	return -1;
}

/* find and load a dll. Return non zero if not found */
/* XXX: add '-rpath' option support ? */
ST_FUNC int tcc_add_dll(TCCState *tcc_state, const char *filename, int flags)
{
	return tcc_add_library_internal(tcc_state, "%s/%s", filename, flags,
		tcc_state->library_paths, tcc_state->nb_library_paths);
}

ST_FUNC int tcc_add_crt(TCCState *tcc_state, const char *filename)
{
	if (-1 == tcc_add_library_internal(tcc_state, "%s/%s",
		filename, 0, tcc_state->crt_paths, tcc_state->nb_crt_paths))
		tcc_error_noabort(tcc_state, "file '%s' not found", filename);
	return 0;
}

/* the library name is the same as the argument of the '-l' option */
LIBTCCAPI int tcc_add_library(TCCState *tcc_state, const char *libraryname)
{
#ifdef TCC_TARGET_PE
	const char *libs[] = { "%s/%s.def", "%s/lib%s.def", "%s/%s.dll", "%s/lib%s.dll", "%s/lib%s.a", NULL };
	const char **pp = tcc_state->static_link ? libs + 4 : libs;
#else
	const char *libs[] = { "%s/lib%s.so", "%s/lib%s.a", NULL };
	const char **pp = tcc_state->static_link ? libs + 1 : libs;
#endif
	while (*pp) {
		if (0 == tcc_add_library_internal(tcc_state, *pp,
			libraryname, 0, tcc_state->library_paths, tcc_state->nb_library_paths))
			return 0;
		++pp;
	}
	return -1;
}

LIBTCCAPI int tcc_add_symbol(TCCState *tcc_state, const char *name, const void *val)
{
#ifdef TCC_TARGET_PE
	/* On x86_64 'val' might not be reachable with a 32bit offset.
	So it is handled here as if it were in a DLL. */
	pe_putimport(tcc_state, 0, name, (uintptr_t)val);
#else
	add_elf_sym(tcc_state, tcc_state->symtab_section, (uintptr_t)val, 0,
		ELFW(ST_INFO)(STB_GLOBAL, STT_NOTYPE), 0,
		SHN_ABS, name);
#endif
	return 0;
}

LIBTCCAPI int tcc_set_output_type(TCCState *tcc_state, int output_type)
{
	tcc_state->output_type = output_type;

	if (!tcc_state->nostdinc) {
		/* default include paths */
		/* -isystem paths have already been handled */
		tcc_add_sysinclude_path(tcc_state, CONFIG_TCC_SYSINCLUDEPATHS);
	}

	/* if bound checking, then add corresponding sections */
#ifdef CONFIG_TCC_BCHECK
	if (tcc_state->do_bounds_check) {
		/* define symbol */
		tcc_define_symbol(tcc_state, "__BOUNDS_CHECKING_ON", NULL);
		/* create bounds sections */
		tcc_state->bounds_section = new_section(tcc_state, ".bounds",
			SHT_PROGBITS, SHF_ALLOC);
		tcc_state->lbounds_section = new_section(tcc_state, ".lbounds",
			SHT_PROGBITS, SHF_ALLOC);
	}
#endif

	if (tcc_state->char_is_unsigned) {
		tcc_define_symbol(tcc_state, "__CHAR_UNSIGNED__", NULL);
	}

	/* add debug sections */
	if (tcc_state->do_debug) {
		/* stab symbols */
		tcc_state->stab_section = new_section(tcc_state, ".stab", SHT_PROGBITS, 0);
		tcc_state->stab_section->sh_entsize = sizeof(Stab_Sym);
		tcc_state->stabstr_section = new_section(tcc_state, ".stabstr", SHT_STRTAB, 0);
		put_elf_str(tcc_state, tcc_state->stabstr_section, "");
		tcc_state->stab_section->link = tcc_state->stabstr_section;
		/* put first entry */
		put_stabs(tcc_state, "", 0, 0, 0, 0);
	}

	tcc_add_library_path(tcc_state, CONFIG_TCC_LIBPATHS);
#ifdef TCC_TARGET_PE
# ifdef _WIN32
	tcc_add_systemdir(tcc_state);
# endif
#else
	/* add libc crt1/crti objects */
	if ((output_type == TCC_OUTPUT_EXE || output_type == TCC_OUTPUT_DLL) &&
		!tcc_state->nostdlib) {
		if (output_type != TCC_OUTPUT_DLL)
			tcc_add_crt(tcc_state, "crt1.o");
		tcc_add_crt(tcc_state, "crti.o");
	}
#endif
	return 0;
}

LIBTCCAPI void tcc_set_lib_path(TCCState *tcc_state, const char *path)
{
	tcc_free(tcc_state, tcc_state->tcc_lib_path);
	tcc_state->tcc_lib_path = tcc_strdup(tcc_state, path);
}

#define WD_ALL    0x0001 /* warning is activated when using -Wall */
#define FD_INVERT 0x0002 /* invert value before storing */

typedef struct FlagDef {
	uint16_t offset;
	uint16_t flags;
	const char *name;
} FlagDef;

static const FlagDef warning_defs[] = {
		{ offsetof(TCCState, warn_unsupported), 0, "unsupported" },
		{ offsetof(TCCState, warn_write_strings), 0, "write-strings" },
		{ offsetof(TCCState, warn_error), 0, "error" },
		{ offsetof(TCCState, warn_implicit_function_declaration), WD_ALL,
		"implicit-function-declaration" },
};

ST_FUNC int set_flag(TCCState *tcc_state, const FlagDef *flags, int nb_flags,
	const char *name, int value)
{
	int i;
	const FlagDef *p;
	const char *r;

	r = name;
	if (r[0] == 'n' && r[1] == 'o' && r[2] == '-') {
		r += 3;
		value = !value;
	}
	for (i = 0, p = flags; i < nb_flags; i++, p++) {
		if (!strcmp(r, p->name))
			goto found;
	}
	return -1;
found:
	if (p->flags & FD_INVERT)
		value = !value;
	*(int *)((uint8_t *)tcc_state + p->offset) = value;
	return 0;
}

/* set/reset a warning */
static int tcc_set_warning(TCCState *tcc_state, const char *warning_name, int value)
{
	int i;
	const FlagDef *p;

	if (!strcmp(warning_name, "all")) {
		for (i = 0, p = warning_defs; i < countof(warning_defs); i++, p++) {
			if (p->flags & WD_ALL)
				*(int *)((uint8_t *)tcc_state + p->offset) = 1;
		}
		return 0;
	}
	else {
		return set_flag(tcc_state, warning_defs, countof(warning_defs),
			warning_name, value);
	}
}

static const FlagDef flag_defs[] = {
		{ offsetof(TCCState, char_is_unsigned), 0, "unsigned-char" },
		{ offsetof(TCCState, char_is_unsigned), FD_INVERT, "signed-char" },
		{ offsetof(TCCState, nocommon), FD_INVERT, "common" },
		{ offsetof(TCCState, leading_underscore), 0, "leading-underscore" },
};

/* set/reset a flag */
static int tcc_set_flag(TCCState *tcc_state, const char *flag_name, int value)
{
	return set_flag(tcc_state, flag_defs, countof(flag_defs),
		flag_name, value);
}


static int strstart(const char *val, const char **str)
{
	const char *p, *q;
	p = *str;
	q = val;
	while (*q) {
		if (*p != *q)
			return 0;
		p++;
		q++;
	}
	*str = p;
	return 1;
}

/* Like strstart, but automatically takes into account that ld options can
*
* - start with double or single dash (e.g. '--soname' or '-soname')
* - arguments can be given as separate or after '=' (e.g. '-Wl,-soname,x.so'
*   or '-Wl,-soname=x.so')
*
* you provide `val` always in 'option[=]' form (no leading -)
*/
static int link_option(const char *str, const char *val, const char **ptr)
{
	const char *p, *q;

	/* there should be 1 or 2 dashes */
	if (*str++ != '-')
		return 0;
	if (*str == '-')
		str++;

	/* then str & val should match (potentialy up to '=') */
	p = str;
	q = val;

	while (*q != '\0' && *q != '=') {
		if (*p != *q)
			return 0;
		p++;
		q++;
	}

	/* '=' near eos means ',' or '=' is ok */
	if (*q == '=') {
		if (*p != ',' && *p != '=')
			return 0;
		p++;
		q++;
	}

	if (ptr)
		*ptr = p;
	return 1;
}

static const char *skip_linker_arg(const char **str)
{
	const char *s1 = *str;
	const char *s2 = strchr(s1, ',');
	*str = s2 ? s2++ : (s2 = s1 + strlen(s1));
	return s2;
}

static char *copy_linker_arg(TCCState *tcc_state, const char *p)
{
	const char *q = p;
	skip_linker_arg(&q);
	return pstrncpy(tcc_malloc(tcc_state, q - p + 1), p, q - p);
}

/* set linker options */
static int tcc_set_linker(TCCState *s, const char *option)
{
	while (option && *option) {

		const char *p = option;
		char *end = NULL;
		int ignoring = 0;

		if (link_option(option, "Bsymbolic", &p)) {
			s->symbolic = 1;
		}
		else if (link_option(option, "nostdlib", &p)) {
			s->nostdlib = 1;
		}
		else if (link_option(option, "fini=", &p)) {
			s->fini_symbol = copy_linker_arg(s, p);
			ignoring = 1;
		}
		else if (link_option(option, "image-base=", &p)
			|| link_option(option, "Ttext=", &p)) {
			s->text_addr = strtoull(p, &end, 16);
			s->has_text_addr = 1;
		}
		else if (link_option(option, "init=", &p)) {
			s->init_symbol = copy_linker_arg(s, p);
			ignoring = 1;
		}
		else if (link_option(option, "oformat=", &p)) {
#if defined(TCC_TARGET_PE)
			if (strstart("pe-", &p)) {
#elif defined(TCC_TARGET_X86_64)
			if (strstart("elf64-", &p)) {
#else
			if (strstart("elf32-", &p)) {
#endif
				s->output_format = TCC_OUTPUT_FORMAT_ELF;
			}
			else if (!strcmp(p, "binary")) {
				s->output_format = TCC_OUTPUT_FORMAT_BINARY;
#ifdef TCC_TARGET_COFF
			}
			else if (!strcmp(p, "coff")) {
				s->output_format = TCC_OUTPUT_FORMAT_COFF;
#endif
			}
			else
				goto err;

			}
		else if (link_option(option, "as-needed", &p)) {
			ignoring = 1;
		}
		else if (link_option(option, "O", &p)) {
			ignoring = 1;
		}
		else if (link_option(option, "rpath=", &p)) {
			s->rpath = copy_linker_arg(s, p);
		}
		else if (link_option(option, "section-alignment=", &p)) {
			s->section_align = strtoul(p, &end, 16);
		}
		else if (link_option(option, "soname=", &p)) {
			s->soname = copy_linker_arg(s, p);
#ifdef TCC_TARGET_PE
		}
		else if (link_option(option, "file-alignment=", &p)) {
			s->pe_file_align = strtoul(p, &end, 16);
		}
		else if (link_option(option, "stack=", &p)) {
			s->pe_stack_size = strtoul(p, &end, 10);
		}
		else if (link_option(option, "subsystem=", &p)) {
#if defined(TCC_TARGET_I386) || defined(TCC_TARGET_X86_64)
			if (!strcmp(p, "native")) {
				s->pe_subsystem = 1;
			}
			else if (!strcmp(p, "console")) {
				s->pe_subsystem = 3;
			}
			else if (!strcmp(p, "gui")) {
				s->pe_subsystem = 2;
			}
			else if (!strcmp(p, "posix")) {
				s->pe_subsystem = 7;
			}
			else if (!strcmp(p, "efiapp")) {
				s->pe_subsystem = 10;
			}
			else if (!strcmp(p, "efiboot")) {
				s->pe_subsystem = 11;
			}
			else if (!strcmp(p, "efiruntime")) {
				s->pe_subsystem = 12;
			}
			else if (!strcmp(p, "efirom")) {
				s->pe_subsystem = 13;
#elif defined(TCC_TARGET_ARM)
			if (!strcmp(p, "wince")) {
				s->pe_subsystem = 9;
#endif
			}
			else
				goto err;
#endif
			}
		else
			goto err;

		if (ignoring && s->warn_unsupported) err: {
			char buf[100], *e;
			pstrcpy(buf, sizeof buf, e = copy_linker_arg(s, option)), tcc_free(s, e);
			if (ignoring)
				tcc_warning(s, "unsupported linker option '%s'", buf);
			else
				tcc_error(s, "unsupported linker option '%s'", buf);
		}
		option = skip_linker_arg(&p);
		}
	return 0;
			}

typedef struct TCCOption {
	const char *name;
	uint16_t index;
	uint16_t flags;
} TCCOption;

enum {
	TCC_OPTION_HELP,
	TCC_OPTION_I,
	TCC_OPTION_D,
	TCC_OPTION_U,
	TCC_OPTION_L,
	TCC_OPTION_B,
	TCC_OPTION_l,
	TCC_OPTION_bench,
	TCC_OPTION_bt,
	TCC_OPTION_b,
	TCC_OPTION_g,
	TCC_OPTION_c,
	TCC_OPTION_float_abi,
	TCC_OPTION_static,
	TCC_OPTION_shared,
	TCC_OPTION_soname,
	TCC_OPTION_o,
	TCC_OPTION_r,
	TCC_OPTION_s,
	TCC_OPTION_Wl,
	TCC_OPTION_W,
	TCC_OPTION_O,
	TCC_OPTION_m,
	TCC_OPTION_f,
	TCC_OPTION_isystem,
	TCC_OPTION_nostdinc,
	TCC_OPTION_nostdlib,
	TCC_OPTION_print_search_dirs,
	TCC_OPTION_rdynamic,
	TCC_OPTION_pedantic,
	TCC_OPTION_pthread,
	TCC_OPTION_run,
	TCC_OPTION_v,
	TCC_OPTION_w,
	TCC_OPTION_pipe,
	TCC_OPTION_E,
	TCC_OPTION_MD,
	TCC_OPTION_MF,
	TCC_OPTION_x,
	TCC_OPTION_dumpversion,
};

#define TCC_OPTION_HAS_ARG 0x0001
#define TCC_OPTION_NOSEP   0x0002 /* cannot have space before option and arg */

static const TCCOption tcc_options[] = {
		{ "h", TCC_OPTION_HELP, 0 },
		{ "-help", TCC_OPTION_HELP, 0 },
		{ "?", TCC_OPTION_HELP, 0 },
		{ "I", TCC_OPTION_I, TCC_OPTION_HAS_ARG },
		{ "D", TCC_OPTION_D, TCC_OPTION_HAS_ARG },
		{ "U", TCC_OPTION_U, TCC_OPTION_HAS_ARG },
		{ "L", TCC_OPTION_L, TCC_OPTION_HAS_ARG },
		{ "B", TCC_OPTION_B, TCC_OPTION_HAS_ARG },
		{ "l", TCC_OPTION_l, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
		{ "bench", TCC_OPTION_bench, 0 },
#ifdef CONFIG_TCC_BACKTRACE
		{ "bt", TCC_OPTION_bt, TCC_OPTION_HAS_ARG },
#endif
#ifdef CONFIG_TCC_BCHECK
		{ "b", TCC_OPTION_b, 0 },
#endif
		{ "g", TCC_OPTION_g, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
		{ "c", TCC_OPTION_c, 0 },
#ifdef TCC_TARGET_ARM
		{ "mfloat-abi", TCC_OPTION_float_abi, TCC_OPTION_HAS_ARG },
#endif
		{ "static", TCC_OPTION_static, 0 },
		{ "shared", TCC_OPTION_shared, 0 },
		{ "soname", TCC_OPTION_soname, TCC_OPTION_HAS_ARG },
		{ "o", TCC_OPTION_o, TCC_OPTION_HAS_ARG },
		{ "pedantic", TCC_OPTION_pedantic, 0 },
		{ "pthread", TCC_OPTION_pthread, 0 },
		{ "run", TCC_OPTION_run, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
		{ "rdynamic", TCC_OPTION_rdynamic, 0 },
		{ "r", TCC_OPTION_r, 0 },
		{ "s", TCC_OPTION_s, 0 },
		{ "Wl,", TCC_OPTION_Wl, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
		{ "W", TCC_OPTION_W, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
		{ "O", TCC_OPTION_O, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
		{ "m", TCC_OPTION_m, TCC_OPTION_HAS_ARG },
		{ "f", TCC_OPTION_f, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
		{ "isystem", TCC_OPTION_isystem, TCC_OPTION_HAS_ARG },
		{ "nostdinc", TCC_OPTION_nostdinc, 0 },
		{ "nostdlib", TCC_OPTION_nostdlib, 0 },
		{ "print-search-dirs", TCC_OPTION_print_search_dirs, 0 },
		{ "v", TCC_OPTION_v, TCC_OPTION_HAS_ARG | TCC_OPTION_NOSEP },
		{ "w", TCC_OPTION_w, 0 },
		{ "pipe", TCC_OPTION_pipe, 0 },
		{ "E", TCC_OPTION_E, 0 },
		{ "MD", TCC_OPTION_MD, 0 },
		{ "MF", TCC_OPTION_MF, TCC_OPTION_HAS_ARG },
		{ "x", TCC_OPTION_x, TCC_OPTION_HAS_ARG },
		{ "dumpversion", TCC_OPTION_dumpversion, 0 },
		{ NULL, 0, 0 },
};

static void parse_option_D(TCCState *tcc_state, const char *optarg)
{
	char *sym = tcc_strdup(tcc_state, optarg);
	char *value = strchr(sym, '=');
	if (value)
		*value++ = '\0';
	tcc_define_symbol(tcc_state, sym, value);
	tcc_free(tcc_state, sym);
}

PUB_FUNC int tcc_parse_args(TCCState *s, int argc, char **argv)
{
	const TCCOption *popt;
	const char *optarg, *r;
	int run = 0;
	int pthread = 0;
	int optind = 0;

	/* collect -Wl options for input such as "-Wl,-rpath -Wl,<path>" */
	CString linker_arg;
	cstr_new(&linker_arg);

	while (optind < argc) {

		r = argv[optind++];
		if (r[0] != '-' || r[1] == '\0') {
			/* add a new file */
			dynarray_add(s, (void ***)&s->files, &s->nb_files, tcc_strdup(s, r));
			if (run) {
				optind--;
				/* argv[0] will be this file */
				break;
			}
			continue;
		}

		/* find option in table */
		for (popt = tcc_options;; ++popt) {
			const char *p1 = popt->name;
			const char *r1 = r + 1;
			if (p1 == NULL)
				tcc_error(s, "invalid option -- '%s'", r);
			if (!strstart(p1, &r1))
				continue;
			optarg = r1;
			if (popt->flags & TCC_OPTION_HAS_ARG) {
				if (*r1 == '\0' && !(popt->flags & TCC_OPTION_NOSEP)) {
					if (optind >= argc)
						tcc_error(s, "argument to '%s' is missing", r);
					optarg = argv[optind++];
				}
			}
			else if (*r1 != '\0')
				continue;
			break;
		}

		switch (popt->index) {
		case TCC_OPTION_HELP:
			return 0;
		case TCC_OPTION_I:
			if (tcc_add_include_path(s, optarg) < 0)
				tcc_error(s, "too many include paths");
			break;
		case TCC_OPTION_D:
			parse_option_D(s, optarg);
			break;
		case TCC_OPTION_U:
			tcc_undefine_symbol(s, optarg);
			break;
		case TCC_OPTION_L:
			tcc_add_library_path(s, optarg);
			break;
		case TCC_OPTION_B:
			/* set tcc utilities path (mainly for tcc development) */
			tcc_set_lib_path(s, optarg);
			break;
		case TCC_OPTION_l:
			dynarray_add(s, (void ***)&s->files, &s->nb_files, tcc_strdup(s, r));
			s->nb_libraries++;
			break;
		case TCC_OPTION_pthread:
			parse_option_D(s, "_REENTRANT");
			pthread = 1;
			break;
		case TCC_OPTION_bench:
			s->do_bench = 1;
			break;
#ifdef CONFIG_TCC_BACKTRACE
		case TCC_OPTION_bt:
			tcc_set_num_callers(atoi(optarg));
			break;
#endif
#ifdef CONFIG_TCC_BCHECK
		case TCC_OPTION_b:
			s->do_bounds_check = 1;
			s->do_debug = 1;
			break;
#endif
		case TCC_OPTION_g:
			s->do_debug = 1;
			break;
		case TCC_OPTION_c:
			s->output_type = TCC_OUTPUT_OBJ;
			break;
#ifdef TCC_TARGET_ARM
		case TCC_OPTION_float_abi:
			/* tcc doesn't support soft float yet */
			if (!strcmp(optarg, "softfp")) {
				s->float_abi = ARM_SOFTFP_FLOAT;
				tcc_undefine_symbol(s, "__ARM_PCS_VFP");
			}
			else if (!strcmp(optarg, "hard"))
				s->float_abi = ARM_HARD_FLOAT;
			else
				tcc_error(s, "unsupported float abi '%s'", optarg);
			break;
#endif
		case TCC_OPTION_static:
			s->static_link = 1;
			break;
		case TCC_OPTION_shared:
			s->output_type = TCC_OUTPUT_DLL;
			break;
		case TCC_OPTION_soname:
			s->soname = tcc_strdup(s, optarg);
			break;
		case TCC_OPTION_m:
			s->option_m = tcc_strdup(s, optarg);
			break;
		case TCC_OPTION_o:
			s->outfile = tcc_strdup(s, optarg);
			break;
		case TCC_OPTION_r:
			/* generate a .o merging several output files */
			s->option_r = 1;
			s->output_type = TCC_OUTPUT_OBJ;
			break;
		case TCC_OPTION_isystem:
			tcc_add_sysinclude_path(s, optarg);
			break;
		case TCC_OPTION_nostdinc:
			s->nostdinc = 1;
			break;
		case TCC_OPTION_nostdlib:
			s->nostdlib = 1;
			break;
		case TCC_OPTION_print_search_dirs:
			s->print_search_dirs = 1;
			break;
		case TCC_OPTION_run:
			s->output_type = TCC_OUTPUT_MEMORY;
			tcc_set_options(s, optarg);
			run = 1;
			break;
		case TCC_OPTION_v:
			do ++s->verbose; while (*optarg++ == 'v');
			break;
		case TCC_OPTION_f:
			if (tcc_set_flag(s, optarg, 1) < 0 && s->warn_unsupported)
				goto unsupported_option;
			break;
		case TCC_OPTION_W:
			if (tcc_set_warning(s, optarg, 1) < 0 &&
				s->warn_unsupported)
				goto unsupported_option;
			break;
		case TCC_OPTION_w:
			s->warn_none = 1;
			break;
		case TCC_OPTION_rdynamic:
			s->rdynamic = 1;
			break;
		case TCC_OPTION_Wl:
			if (linker_arg.size)
				--linker_arg.size, cstr_ccat(s, &linker_arg, ',');
			cstr_cat(s, &linker_arg, optarg);
			cstr_ccat(s, &linker_arg, '\0');
			break;
		case TCC_OPTION_E:
			s->output_type = TCC_OUTPUT_PREPROCESS;
			break;
		case TCC_OPTION_MD:
			s->gen_deps = 1;
			break;
		case TCC_OPTION_MF:
			s->deps_outfile = tcc_strdup(s, optarg);
			break;
		case TCC_OPTION_dumpversion:
			printf("%s\n", TCC_VERSION);
			exit(0);
		case TCC_OPTION_O:
		case TCC_OPTION_pedantic:
		case TCC_OPTION_pipe:
		case TCC_OPTION_s:
		case TCC_OPTION_x:
			/* ignored */
			break;
		default:
			if (s->warn_unsupported) {
			unsupported_option:
				tcc_warning(s, "unsupported option '%s'", r);
			}
			break;
		}
	}

	if (pthread && s->output_type != TCC_OUTPUT_OBJ)
		tcc_set_options(s, "-lpthread");

	tcc_set_linker(s, (const char *)linker_arg.data);
	cstr_free(s, &linker_arg);

	return optind;
}

LIBTCCAPI int tcc_set_options(TCCState *tcc_state, const char *str)
{
	const char *s1;
	char **argv, *arg;
	int argc, len;
	int ret;

	argc = 0, argv = NULL;
	for (;;) {
		while (is_space(*str))
			str++;
		if (*str == '\0')
			break;
		s1 = str;
		while (*str != '\0' && !is_space(*str))
			str++;
		len = str - s1;
		arg = tcc_malloc(tcc_state, len + 1);
		pstrncpy(arg, s1, len);
		dynarray_add(tcc_state, (void ***)&argv, &argc, arg);
	}
	ret = tcc_parse_args(tcc_state, argc, argv);
	dynarray_reset(tcc_state, &argv, &argc);
	return ret;
}

PUB_FUNC void tcc_print_stats(TCCState *tcc_state, int64_t total_time)
{
	double tt;
	tt = (double)total_time / 1000000.0;
	if (tt < 0.001)
		tt = 0.001;
	if (tcc_state->total_bytes < 1)
		tcc_state->total_bytes = 1;
	printf("%d idents, %d lines, %d bytes, %0.3f s, %d lines/s, %0.1f MB/s\n",
		tcc_state->tok_ident - TOK_IDENT, tcc_state->total_lines, tcc_state->total_bytes,
		tt, (int)(tcc_state->total_lines / tt),
		tcc_state->total_bytes / tt / 1000000.0);
}

PUB_FUNC void tcc_set_environment(TCCState *tcc_state)
{
	char * path;

	path = getenv("C_INCLUDE_PATH");
	if (path != NULL) {
		tcc_add_include_path(tcc_state, path);
	}
	path = getenv("CPATH");
	if (path != NULL) {
		tcc_add_include_path(tcc_state, path);
	}
	path = getenv("LIBRARY_PATH");
	if (path != NULL) {
		tcc_add_library_path(tcc_state, path);
	}
}
