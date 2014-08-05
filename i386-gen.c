/*
*  X86 code generator for TCC
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

#ifdef TARGET_DEFS_ONLY

/* number of available registers */
#define NB_REGS         4
#define NB_ASM_REGS     8

/* a register can belong to several classes. The classes must be
sorted from more general to more precise (see gv2() code which does
assumptions on it). */
#define RC_INT     0x0001 /* generic integer register */
#define RC_FLOAT   0x0002 /* generic float register */
#define RC_EAX     0x0004
#define RC_ST0     0x0008 
#define RC_ECX     0x0010
#define RC_EDX     0x0020
#define RC_IRET    RC_EAX /* function return: integer register */
#define RC_LRET    RC_EDX /* function return: second integer register */
#define RC_FRET    RC_ST0 /* function return: float register */

/* pretty names for the registers */
enum {
	TREG_EAX = 0,
	TREG_ECX,
	TREG_EDX,
	TREG_ST0,
	TREG_ESP = 4
};

/* return registers for function */
#define REG_IRET TREG_EAX /* single word int return register */
#define REG_LRET TREG_EDX /* second word return register (for long long) */
#define REG_FRET TREG_ST0 /* float return register */

/* defined if function parameters must be evaluated in reverse order */
#define INVERT_FUNC_PARAMS

/* defined if structures are passed as pointers. Otherwise structures
are directly pushed on stack. */
/* #define FUNC_STRUCT_PARAM_AS_PTR */

/* pointer size, in bytes */
#define PTR_SIZE 4

/* long double size and alignment, in bytes */
#define LDOUBLE_SIZE  12
#define LDOUBLE_ALIGN 4
/* maximum alignment (for aligned attribute support) */
#define MAX_ALIGN     8


#define psym oad

/******************************************************/
/* ELF defines */

#define EM_TCC_TARGET EM_386

/* relocation type for 32 bit data relocation */
#define R_DATA_32   R_386_32
#define R_DATA_PTR  R_386_32
#define R_JMP_SLOT  R_386_JMP_SLOT
#define R_COPY      R_386_COPY

#define ELF_START_ADDR 0x08048000
#define ELF_PAGE_SIZE  0x1000

/******************************************************/
#else /* ! TARGET_DEFS_ONLY */
/******************************************************/
#include "tcc.h"

ST_DATA const int reg_classes[NB_REGS] = {
	/* eax */ RC_INT | RC_EAX,
	/* ecx */ RC_INT | RC_ECX,
	/* edx */ RC_INT | RC_EDX,
	/* st0 */ RC_FLOAT | RC_ST0,
};

static unsigned long func_sub_sp_offset;
static int func_ret_sub;
#ifdef CONFIG_TCC_BCHECK
static unsigned long func_bound_offset;
#endif

/* XXX: make it faster ? */
ST_FUNC void g(TCCState *tcc_state, int c)
{
	int ind1;
	ind1 = tcc_state->ind + 1;
	if (ind1 > tcc_state->cur_text_section->data_allocated)
		section_realloc(tcc_state, tcc_state->cur_text_section, ind1);
	tcc_state->cur_text_section->data[tcc_state->ind] = c;
	tcc_state->ind = ind1;
}

ST_FUNC void o(TCCState *tcc_state, unsigned int c)
{
	while (c) {
		g(tcc_state, c);
		c = c >> 8;
	}
}

ST_FUNC void gen_le16(TCCState *tcc_state, int v)
{
	g(tcc_state, v);
	g(tcc_state, v >> 8);
}

ST_FUNC void gen_le32(TCCState *tcc_state, int c)
{
	g(tcc_state, c);
	g(tcc_state, c >> 8);
	g(tcc_state, c >> 16);
	g(tcc_state, c >> 24);
}

/* output a symbol and patch all calls to it */
ST_FUNC void gsym_addr(TCCState *tcc_state, int t, int a)
{
	int n, *ptr;
	while (t) {
		ptr = (int *)(tcc_state->cur_text_section->data + t);
		n = *ptr; /* next value */
		*ptr = a - t - 4;
		t = n;
	}
}

ST_FUNC void gsym(TCCState *tcc_state, int t)
{
	gsym_addr(tcc_state, t, tcc_state->ind);
}

/* psym is used to put an instruction with a data field which is a
reference to a symbol. It is in fact the same as oad ! */
#define psym oad

/* instruction + 4 bytes data. Return the address of the data */
ST_FUNC int oad(TCCState *tcc_state, int c, int s)
{
	int ind1;

	o(tcc_state, c);
	ind1 = tcc_state->ind + 4;
	if (ind1 > tcc_state->cur_text_section->data_allocated)
		section_realloc(tcc_state, tcc_state->cur_text_section, ind1);
	*(int *)(tcc_state->cur_text_section->data + tcc_state->ind) = s;
	s = tcc_state->ind;
	tcc_state->ind = ind1;
	return s;
}

/* output constant with relocation if 'r & VT_SYM' is true */
ST_FUNC void gen_addr32(TCCState *tcc_state, int r, Sym *sym, int c)
{
	if (r & VT_SYM)
		greloc(tcc_state, tcc_state->cur_text_section, sym, tcc_state->ind, R_386_32);
	gen_le32(tcc_state, c);
}

ST_FUNC void gen_addrpc32(TCCState *tcc_state, int r, Sym *sym, int c)
{
	if (r & VT_SYM)
		greloc(tcc_state, tcc_state->cur_text_section, sym, tcc_state->ind, R_386_PC32);
	gen_le32(tcc_state, c - 4);
}

/* generate a modrm reference. 'op_reg' contains the addtionnal 3
opcode bits */
static void gen_modrm(TCCState *tcc_state, int op_reg, int r, Sym *sym, int c)
{
	op_reg = op_reg << 3;
	if ((r & VT_VALMASK) == VT_CONST) {
		/* constant memory reference */
		o(tcc_state, 0x05 | op_reg);
		gen_addr32(tcc_state, r, sym, c);
	}
	else if ((r & VT_VALMASK) == VT_LOCAL) {
		/* currently, we use only ebp as base */
		if (c == (char)c) {
			/* short reference */
			o(tcc_state, 0x45 | op_reg);
			g(tcc_state, c);
		}
		else {
			oad(tcc_state, 0x85 | op_reg, c);
		}
	}
	else {
		g(tcc_state, 0x00 | op_reg | (r & VT_VALMASK));
	}
}

/* load 'r' from value 'sv' */
ST_FUNC void load(TCCState *tcc_state, int r, SValue *sv)
{
	int v, t, ft, fc, fr;
	SValue v1;

#ifdef TCC_TARGET_PE
	SValue v2;
	sv = pe_getimport(tcc_state, sv, &v2);
#endif

	fr = sv->r;
	ft = sv->type.t;
	fc = sv->c.ul;

	v = fr & VT_VALMASK;
	if (fr & VT_LVAL) {
		if (v == VT_LLOCAL) {
			v1.type.t = VT_INT;
			v1.r = VT_LOCAL | VT_LVAL;
			v1.c.ul = fc;
			fr = r;
			if (!(reg_classes[fr] & RC_INT))
				fr = get_reg(tcc_state, RC_INT);
			load(tcc_state, fr, &v1);
		}
		if ((ft & VT_BTYPE) == VT_FLOAT) {
			o(tcc_state, 0xd9); /* flds */
			r = 0;
		}
		else if ((ft & VT_BTYPE) == VT_DOUBLE) {
			o(tcc_state, 0xdd); /* fldl */
			r = 0;
		}
		else if ((ft & VT_BTYPE) == VT_LDOUBLE) {
			o(tcc_state, 0xdb); /* fldt */
			r = 5;
		}
		else if ((ft & VT_TYPE) == VT_BYTE || (ft & VT_TYPE) == VT_BOOL) {
			o(tcc_state, 0xbe0f);   /* movsbl */
		}
		else if ((ft & VT_TYPE) == (VT_BYTE | VT_UNSIGNED)) {
			o(tcc_state, 0xb60f);   /* movzbl */
		}
		else if ((ft & VT_TYPE) == VT_SHORT) {
			o(tcc_state, 0xbf0f);   /* movswl */
		}
		else if ((ft & VT_TYPE) == (VT_SHORT | VT_UNSIGNED)) {
			o(tcc_state, 0xb70f);   /* movzwl */
		}
		else {
			o(tcc_state, 0x8b);     /* movl */
		}
		gen_modrm(tcc_state, r, fr, sv->sym, fc);
	}
	else {
		if (v == VT_CONST) {
			o(tcc_state, 0xb8 + r); /* mov $xx, r */
			gen_addr32(tcc_state, fr, sv->sym, fc);
		}
		else if (v == VT_LOCAL) {
			if (fc) {
				o(tcc_state, 0x8d); /* lea xxx(%ebp), r */
				gen_modrm(tcc_state, r, VT_LOCAL, sv->sym, fc);
			}
			else {
				o(tcc_state, 0x89);
				o(tcc_state, 0xe8 + r); /* mov %ebp, r */
			}
		}
		else if (v == VT_CMP) {
			oad(tcc_state, 0xb8 + r, 0); /* mov $0, r */
			o(tcc_state, 0x0f); /* setxx %br */
			o(tcc_state, fc);
			o(tcc_state, 0xc0 + r);
		}
		else if (v == VT_JMP || v == VT_JMPI) {
			t = v & 1;
			oad(tcc_state, 0xb8 + r, t); /* mov $1, r */
			o(tcc_state, 0x05eb); /* jmp after */
			gsym(tcc_state, fc);
			oad(tcc_state, 0xb8 + r, t ^ 1); /* mov $0, r */
		}
		else if (v != r) {
			o(tcc_state, 0x89);
			o(tcc_state, 0xc0 + r + v * 8); /* mov v, r */
		}
	}
}

/* store register 'r' in lvalue 'v' */
ST_FUNC void store(TCCState *tcc_state, int r, SValue *v)
{
	int fr, bt, ft, fc;

#ifdef TCC_TARGET_PE
	SValue v2;
	v = pe_getimport(tcc_state, v, &v2);
#endif

	ft = v->type.t;
	fc = v->c.ul;
	fr = v->r & VT_VALMASK;
	bt = ft & VT_BTYPE;
	/* XXX: incorrect if float reg to reg */
	if (bt == VT_FLOAT) {
		o(tcc_state, 0xd9); /* fsts */
		r = 2;
	}
	else if (bt == VT_DOUBLE) {
		o(tcc_state, 0xdd); /* fstpl */
		r = 2;
	}
	else if (bt == VT_LDOUBLE) {
		o(tcc_state, 0xc0d9); /* fld %st(0) */
		o(tcc_state, 0xdb); /* fstpt */
		r = 7;
	}
	else {
		if (bt == VT_SHORT)
			o(tcc_state, 0x66);
		if (bt == VT_BYTE || bt == VT_BOOL)
			o(tcc_state, 0x88);
		else
			o(tcc_state, 0x89);
	}
	if (fr == VT_CONST ||
		fr == VT_LOCAL ||
		(v->r & VT_LVAL)) {
		gen_modrm(tcc_state, r, v->r, v->sym, fc);
	}
	else if (fr != r) {
		o(tcc_state, 0xc0 + fr + r * 8); /* mov r, fr */
	}
}

static void gadd_sp(TCCState *tcc_state, int val)
{
	if (val == (char)val) {
		o(tcc_state, 0xc483);
		g(tcc_state, val);
	}
	else {
		oad(tcc_state, 0xc481, val); /* add $xxx, %esp */
	}
}

static void gen_static_call(TCCState *tcc_state, int v)
{
	Sym *sym;

	sym = external_global_sym(tcc_state, v, &tcc_state->func_old_type, 0);
	oad(tcc_state, 0xe8, -4);
	greloc(tcc_state, tcc_state->cur_text_section, sym, tcc_state->ind - 4, R_386_PC32);
}

/* 'is_jmp' is '1' if it is a jump */
static void gcall_or_jmp(TCCState *tcc_state, int is_jmp)
{
	int r;
	if ((tcc_state->vtop->r & (VT_VALMASK | VT_LVAL)) == VT_CONST) {
		/* constant case */
		if (tcc_state->vtop->r & VT_SYM) {
			/* relocation case */
			greloc(tcc_state, tcc_state->cur_text_section, tcc_state->vtop->sym,
				tcc_state->ind + 1, R_386_PC32);
		}
		else {
			/* put an empty PC32 relocation */
			put_elf_reloc(tcc_state, tcc_state->symtab_section, tcc_state->cur_text_section,
				tcc_state->ind + 1, R_386_PC32, 0);
		}
		oad(tcc_state, 0xe8 + is_jmp, tcc_state->vtop->c.ul - 4); /* call/jmp im */
	}
	else {
		/* otherwise, indirect call */
		r = gv(tcc_state, RC_INT);
		o(tcc_state, 0xff); /* call/jmp *r */
		o(tcc_state, 0xd0 + r + (is_jmp << 4));
	}
}

static uint8_t fastcall_regs[3] = { TREG_EAX, TREG_EDX, TREG_ECX };
static uint8_t fastcallw_regs[2] = { TREG_ECX, TREG_EDX };

/* Return the number of registers needed to return the struct, or 0 if
returning via struct pointer. */
ST_FUNC int gfunc_sret(TCCState* tcc_state, CType *vt, int variadic, CType *ret, int *ret_align)
{
#ifdef TCC_TARGET_PE
	int size, align;

	*ret_align = 1; // Never have to re-align return values for x86
	size = type_size(vt, &align);
	if (size > 8) {
		return 0;
	}
	else if (size > 4) {
		ret->ref = NULL;
		ret->t = VT_LLONG;
		return 1;
	}
	else {
		ret->ref = NULL;
		ret->t = VT_INT;
		return 1;
	}
#else
	*ret_align = 1; // Never have to re-align return values for x86
	return 0;
#endif
}

/* Generate function call. The function address is pushed first, then
all the parameters in call order. This functions pops all the
parameters and the function address. */
ST_FUNC void gfunc_call(TCCState* tcc_state, int nb_args)
{
	int size, align, r, args_size, i, func_call;
	Sym *func_sym;

	args_size = 0;
	for (i = 0; i < nb_args; i++) {
		if ((tcc_state->vtop->type.t & VT_BTYPE) == VT_STRUCT) {
			size = type_size(&tcc_state->vtop->type, &align);
			/* align to stack align size */
			size = (size + 3) & ~3;
			/* allocate the necessary size on stack */
			oad(tcc_state, 0xec81, size); /* sub $xxx, %esp */
			/* generate structure store */
			r = get_reg(tcc_state, RC_INT);
			o(tcc_state, 0x89); /* mov %esp, r */
			o(tcc_state, 0xe0 + r);
			vset(tcc_state, &tcc_state->vtop->type, r | VT_LVAL, 0);
			vswap(tcc_state);
			vstore(tcc_state);
			args_size += size;
		}
		else if (is_float(tcc_state->vtop->type.t)) {
			gv(tcc_state, RC_FLOAT); /* only one float register */
			if ((tcc_state->vtop->type.t & VT_BTYPE) == VT_FLOAT)
				size = 4;
			else if ((tcc_state->vtop->type.t & VT_BTYPE) == VT_DOUBLE)
				size = 8;
			else
				size = 12;
			oad(tcc_state, 0xec81, size); /* sub $xxx, %esp */
			if (size == 12)
				o(tcc_state, 0x7cdb);
			else
				o(tcc_state, 0x5cd9 + size - 4); /* fstp[s|l] 0(%esp) */
			g(tcc_state, 0x24);
			g(tcc_state, 0x00);
			args_size += size;
		}
		else {
			/* simple type (currently always same size) */
			/* XXX: implicit cast ? */
			r = gv(tcc_state, RC_INT);
			if ((tcc_state->vtop->type.t & VT_BTYPE) == VT_LLONG) {
				size = 8;
				o(tcc_state, 0x50 + tcc_state->vtop->r2); /* push r */
			}
			else {
				size = 4;
			}
			o(tcc_state, 0x50 + r); /* push r */
			args_size += size;
		}
		tcc_state->vtop--;
	}
	save_regs(tcc_state, 0); /* save used temporary registers */
	func_sym = tcc_state->vtop->type.ref;
	func_call = func_sym->a.func_call;
	/* fast call case */
	if ((func_call >= FUNC_FASTCALL1 && func_call <= FUNC_FASTCALL3) ||
		func_call == FUNC_FASTCALLW) {
		int fastcall_nb_regs;
		uint8_t *fastcall_regs_ptr;
		if (func_call == FUNC_FASTCALLW) {
			fastcall_regs_ptr = fastcallw_regs;
			fastcall_nb_regs = 2;
		}
		else {
			fastcall_regs_ptr = fastcall_regs;
			fastcall_nb_regs = func_call - FUNC_FASTCALL1 + 1;
		}
		for (i = 0; i < fastcall_nb_regs; i++) {
			if (args_size <= 0)
				break;
			o(tcc_state, 0x58 + fastcall_regs_ptr[i]); /* pop r */
			/* XXX: incorrect for struct/floats */
			args_size -= 4;
		}
	}
#ifndef TCC_TARGET_PE
	else if ((tcc_state->vtop->type.ref->type.t & VT_BTYPE) == VT_STRUCT)
		args_size -= 4;
#endif
	gcall_or_jmp(tcc_state, 0);

	if (args_size && func_call != FUNC_STDCALL)
		gadd_sp(tcc_state, args_size);
	tcc_state->vtop--;
}

#ifdef TCC_TARGET_PE
#define FUNC_PROLOG_SIZE 10
#else
#define FUNC_PROLOG_SIZE 9
#endif

/* generate function prolog of type 't' */
ST_FUNC void gfunc_prolog(TCCState* tcc_state, CType *func_type)
{
	int addr, align, size, func_call, fastcall_nb_regs;
	int param_index, param_addr;
	uint8_t *fastcall_regs_ptr;
	Sym *sym;
	CType *type;

	sym = func_type->ref;
	func_call = sym->a.func_call;
	addr = 8;
	tcc_state->loc = 0;
	tcc_state->func_vc = 0;

	if (func_call >= FUNC_FASTCALL1 && func_call <= FUNC_FASTCALL3) {
		fastcall_nb_regs = func_call - FUNC_FASTCALL1 + 1;
		fastcall_regs_ptr = fastcall_regs;
	}
	else if (func_call == FUNC_FASTCALLW) {
		fastcall_nb_regs = 2;
		fastcall_regs_ptr = fastcallw_regs;
	}
	else {
		fastcall_nb_regs = 0;
		fastcall_regs_ptr = NULL;
	}
	param_index = 0;

	tcc_state->ind += FUNC_PROLOG_SIZE;
	func_sub_sp_offset = tcc_state->ind;
	/* if the function returns a structure, then add an
	implicit pointer parameter */
	tcc_state->func_vt = sym->type;
	tcc_state->func_var = (sym->c == FUNC_ELLIPSIS);
#ifdef TCC_TARGET_PE
	size = type_size(&tcc_state->func_vt, &align);
	if (((tcc_state->func_vt.t & VT_BTYPE) == VT_STRUCT) && (size > 8)) {
#else
	if ((tcc_state->func_vt.t & VT_BTYPE) == VT_STRUCT) {
#endif
		/* XXX: fastcall case ? */
		tcc_state->func_vc = addr;
		addr += 4;
		param_index++;
	}
	/* define parameters */
	while ((sym = sym->next) != NULL) {
		type = &sym->type;
		size = type_size(type, &align);
		size = (size + 3) & ~3;
#ifdef FUNC_STRUCT_PARAM_AS_PTR
		/* structs are passed as pointer */
		if ((type->t & VT_BTYPE) == VT_STRUCT) {
			size = 4;
		}
#endif
		if (param_index < fastcall_nb_regs) {
			/* save FASTCALL register */
			tcc_state->loc -= 4;
			o(tcc_state, 0x89);     /* movl */
			gen_modrm(tcc_state, fastcall_regs_ptr[param_index], VT_LOCAL, NULL, tcc_state->loc);
			param_addr = tcc_state->loc;
		}
		else {
			param_addr = addr;
			addr += size;
		}
		sym_push(tcc_state, sym->v & ~SYM_FIELD, type,
			VT_LOCAL | lvalue_type(type->t), param_addr);
		param_index++;
	}
	func_ret_sub = 0;
	/* pascal type call ? */
	if (func_call == FUNC_STDCALL)
		func_ret_sub = addr - 8;
#ifndef TCC_TARGET_PE
	else if (tcc_state->func_vc)
		func_ret_sub = 4;
#endif

#ifdef CONFIG_TCC_BCHECK
	/* leave some room for bound checking code */
	if (tcc_state->do_bounds_check) {
		oad(tcc_state, 0xb8, 0); /* lbound section pointer */
		oad(tcc_state, 0xb8, 0); /* call to function */
		func_bound_offset = tcc_state->lbounds_section->data_offset;
	}
#endif
	}

/* generate function epilog */
ST_FUNC void gfunc_epilog(TCCState* tcc_state)
{
	int v, saved_ind;

#ifdef CONFIG_TCC_BCHECK
	if (tcc_state->do_bounds_check
		&& func_bound_offset != tcc_state->lbounds_section->data_offset) {
		int saved_ind;
		int *bounds_ptr;
		Sym *sym_data;
		/* add end of table info */
		bounds_ptr = section_ptr_add(tcc_state, tcc_state->lbounds_section, sizeof(int));
		*bounds_ptr = 0;
		/* generate bound local allocation */
		saved_ind = tcc_state->ind;
		tcc_state->ind = func_sub_sp_offset;
		sym_data = get_sym_ref(tcc_state, &tcc_state->char_pointer_type, tcc_state->lbounds_section,
			func_bound_offset, tcc_state->lbounds_section->data_offset);
		greloc(tcc_state, tcc_state->cur_text_section, sym_data,
			tcc_state->ind + 1, R_386_32);
		oad(tcc_state, 0xb8, 0); /* mov %eax, xxx */
		gen_static_call(tcc_state, TOK___bound_local_new);

		tcc_state->ind = saved_ind;
		/* generate bound check local freeing */
		o(tcc_state, 0x5250); /* save returned value, if any */
		greloc(tcc_state, tcc_state->cur_text_section, sym_data,
			tcc_state->ind + 1, R_386_32);
		oad(tcc_state, 0xb8, 0); /* mov %eax, xxx */
		gen_static_call(tcc_state, TOK___bound_local_delete);

		o(tcc_state, 0x585a); /* restore returned value, if any */
	}
#endif
	o(tcc_state, 0xc9); /* leave */
	if (func_ret_sub == 0) {
		o(tcc_state, 0xc3); /* ret */
	}
	else {
		o(tcc_state, 0xc2); /* ret n */
		g(tcc_state, func_ret_sub);
		g(tcc_state, func_ret_sub >> 8);
	}
	/* align local size to word & save local variables */

	v = (-tcc_state->loc + 3) & -4;
	saved_ind = tcc_state->ind;
	tcc_state->ind = func_sub_sp_offset - FUNC_PROLOG_SIZE;
#ifdef TCC_TARGET_PE
	if (v >= 4096) {
		oad(tcc_state, 0xb8, v); /* mov stacksize, %eax */
		gen_static_call(tcc_state, TOK___chkstk); /* call __chkstk, (does the stackframe too) */
	}
	else
#endif
	{
		o(tcc_state, 0xe58955);  /* push %ebp, mov %esp, %ebp */
		o(tcc_state, 0xec81);  /* sub esp, stacksize */
		gen_le32(tcc_state, v);
#if FUNC_PROLOG_SIZE == 10
		o(tcc_state, 0x90);  /* adjust to FUNC_PROLOG_SIZE */
#endif
	}
	tcc_state->ind = saved_ind;
}

/* generate a jump to a label */
ST_FUNC int gjmp(TCCState *tcc_state, int t)
{
	return psym(tcc_state, 0xe9, t);
}

/* generate a jump to a fixed address */
ST_FUNC void gjmp_addr(TCCState *tcc_state, int a)
{
	int r;
	r = a - tcc_state->ind - 2;
	if (r == (char)r) {
		g(tcc_state, 0xeb);
		g(tcc_state, r);
	}
	else {
		oad(tcc_state, 0xe9, a - tcc_state->ind - 5);
	}
}

/* generate a test. set 'inv' to invert test. Stack entry is popped */
ST_FUNC int gtst(TCCState *tcc_state, int inv, int t)
{
	int v, *p;

	v = tcc_state->vtop->r & VT_VALMASK;
	if (v == VT_CMP) {
		/* fast case : can jump directly since flags are set */
		g(tcc_state, 0x0f);
		t = psym(tcc_state, (tcc_state->vtop->c.i - 16) ^ inv, t);
	}
	else { /* VT_JMP || VT_JMPI */
		/* && or || optimization */
		if ((v & 1) == inv) {
			/* insert vtop->c jump list in t */
			p = &tcc_state->vtop->c.i;
			while (*p != 0)
				p = (int *)(tcc_state->cur_text_section->data + *p);
			*p = t;
			t = tcc_state->vtop->c.i;
		}
		else {
			t = gjmp(tcc_state, t);
			gsym(tcc_state, tcc_state->vtop->c.i);
		}
	}
	tcc_state->vtop--;
	return t;
}

/* generate an integer binary operation */
ST_FUNC void gen_opi(TCCState* tcc_state, int op)
{
	int r, fr, opc, c;

	switch (op) {
	case '+':
	case TOK_ADDC1: /* add with carry generation */
		opc = 0;
	gen_op8:
		if ((tcc_state->vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
			/* constant case */
			vswap(tcc_state);
			r = gv(tcc_state, RC_INT);
			vswap(tcc_state);
			c = tcc_state->vtop->c.i;
			if (c == (char)c) {
				/* generate inc and dec for smaller code */
				if (c == 1 && opc == 0) {
					o(tcc_state, 0x40 | r); // inc
				}
				else if (c == 1 && opc == 5) {
					o(tcc_state, 0x48 | r); // dec
				}
				else {
					o(tcc_state, 0x83);
					o(tcc_state, 0xc0 | (opc << 3) | r);
					g(tcc_state, c);
				}
			}
			else {
				o(tcc_state, 0x81);
				oad(tcc_state, 0xc0 | (opc << 3) | r, c);
			}
		}
		else {
			gv2(tcc_state, RC_INT, RC_INT);
			r = tcc_state->vtop[-1].r;
			fr = tcc_state->vtop[0].r;
			o(tcc_state, (opc << 3) | 0x01);
			o(tcc_state, 0xc0 + r + fr * 8);
		}
		tcc_state->vtop--;
		if (op >= TOK_ULT && op <= TOK_GT) {
			tcc_state->vtop->r = VT_CMP;
			tcc_state->vtop->c.i = op;
		}
		break;
	case '-':
	case TOK_SUBC1: /* sub with carry generation */
		opc = 5;
		goto gen_op8;
	case TOK_ADDC2: /* add with carry use */
		opc = 2;
		goto gen_op8;
	case TOK_SUBC2: /* sub with carry use */
		opc = 3;
		goto gen_op8;
	case '&':
		opc = 4;
		goto gen_op8;
	case '^':
		opc = 6;
		goto gen_op8;
	case '|':
		opc = 1;
		goto gen_op8;
	case '*':
		gv2(tcc_state, RC_INT, RC_INT);
		r = tcc_state->vtop[-1].r;
		fr = tcc_state->vtop[0].r;
		tcc_state->vtop--;
		o(tcc_state, 0xaf0f); /* imul fr, r */
		o(tcc_state, 0xc0 + fr + r * 8);
		break;
	case TOK_SHL:
		opc = 4;
		goto gen_shift;
	case TOK_SHR:
		opc = 5;
		goto gen_shift;
	case TOK_SAR:
		opc = 7;
	gen_shift:
		opc = 0xc0 | (opc << 3);
		if ((tcc_state->vtop->r & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST) {
			/* constant case */
			vswap(tcc_state);
			r = gv(tcc_state, RC_INT);
			vswap(tcc_state);
			c = tcc_state->vtop->c.i & 0x1f;
			o(tcc_state, 0xc1); /* shl/shr/sar $xxx, r */
			o(tcc_state, opc | r);
			g(tcc_state, c);
		}
		else {
			/* we generate the shift in ecx */
			gv2(tcc_state, RC_INT, RC_ECX);
			r = tcc_state->vtop[-1].r;
			o(tcc_state, 0xd3); /* shl/shr/sar %cl, r */
			o(tcc_state, opc | r);
		}
		tcc_state->vtop--;
		break;
	case '/':
	case TOK_UDIV:
	case TOK_PDIV:
	case '%':
	case TOK_UMOD:
	case TOK_UMULL:
		/* first operand must be in eax */
		/* XXX: need better constraint for second operand */
		gv2(tcc_state, RC_EAX, RC_ECX);
		r = tcc_state->vtop[-1].r;
		fr = tcc_state->vtop[0].r;
		tcc_state->vtop--;
		save_reg(tcc_state, TREG_EDX);
		if (op == TOK_UMULL) {
			o(tcc_state, 0xf7); /* mul fr */
			o(tcc_state, 0xe0 + fr);
			tcc_state->vtop->r2 = TREG_EDX;
			r = TREG_EAX;
		}
		else {
			if (op == TOK_UDIV || op == TOK_UMOD) {
				o(tcc_state, 0xf7d231); /* xor %edx, %edx, div fr, %eax */
				o(tcc_state, 0xf0 + fr);
			}
			else {
				o(tcc_state, 0xf799); /* cltd, idiv fr, %eax */
				o(tcc_state, 0xf8 + fr);
			}
			if (op == '%' || op == TOK_UMOD)
				r = TREG_EDX;
			else
				r = TREG_EAX;
		}
		tcc_state->vtop->r = r;
		break;
	default:
		opc = 7;
		goto gen_op8;
	}
}

/* generate a floating point operation 'v = t1 op t2' instruction. The
two operands are guaranted to have the same floating point type */
/* XXX: need to use ST1 too */
ST_FUNC void gen_opf(TCCState* tcc_state, int op)
{
	int a, ft, fc, swapped, r;

	/* convert constants to memory references */
	if ((tcc_state->vtop[-1].r & (VT_VALMASK | VT_LVAL)) == VT_CONST) {
		vswap(tcc_state);
		gv(tcc_state, RC_FLOAT);
		vswap(tcc_state);
	}
	if ((tcc_state->vtop[0].r & (VT_VALMASK | VT_LVAL)) == VT_CONST)
		gv(tcc_state, RC_FLOAT);

	/* must put at least one value in the floating point register */
	if ((tcc_state->vtop[-1].r & VT_LVAL) &&
		(tcc_state->vtop[0].r & VT_LVAL)) {
		vswap(tcc_state);
		gv(tcc_state, RC_FLOAT);
		vswap(tcc_state);
	}
	swapped = 0;
	/* swap the stack if needed so that t1 is the register and t2 is
	the memory reference */
	if (tcc_state->vtop[-1].r & VT_LVAL) {
		vswap(tcc_state);
		swapped = 1;
	}
	if (op >= TOK_ULT && op <= TOK_GT) {
		/* load on stack second operand */
		load(tcc_state, TREG_ST0, tcc_state->vtop);
		save_reg(tcc_state, TREG_EAX); /* eax is used by FP comparison code */
		if (op == TOK_GE || op == TOK_GT)
			swapped = !swapped;
		else if (op == TOK_EQ || op == TOK_NE)
			swapped = 0;
		if (swapped)
			o(tcc_state, 0xc9d9); /* fxch %st(1) */
		if (op == TOK_EQ || op == TOK_NE)
			o(tcc_state, 0xe9da); /* fucompp */
		else
			o(tcc_state, 0xd9de); /* fcompp */
		o(tcc_state, 0xe0df); /* fnstsw %ax */
		if (op == TOK_EQ) {
			o(tcc_state, 0x45e480); /* and $0x45, %ah */
			o(tcc_state, 0x40fC80); /* cmp $0x40, %ah */
		}
		else if (op == TOK_NE) {
			o(tcc_state, 0x45e480); /* and $0x45, %ah */
			o(tcc_state, 0x40f480); /* xor $0x40, %ah */
			op = TOK_NE;
		}
		else if (op == TOK_GE || op == TOK_LE) {
			o(tcc_state, 0x05c4f6); /* test $0x05, %ah */
			op = TOK_EQ;
		}
		else {
			o(tcc_state, 0x45c4f6); /* test $0x45, %ah */
			op = TOK_EQ;
		}
		tcc_state->vtop--;
		tcc_state->vtop->r = VT_CMP;
		tcc_state->vtop->c.i = op;
	}
	else {
		/* no memory reference possible for long double operations */
		if ((tcc_state->vtop->type.t & VT_BTYPE) == VT_LDOUBLE) {
			load(tcc_state, TREG_ST0, tcc_state->vtop);
			swapped = !swapped;
		}

		switch (op) {
		default:
		case '+':
			a = 0;
			break;
		case '-':
			a = 4;
			if (swapped)
				a++;
			break;
		case '*':
			a = 1;
			break;
		case '/':
			a = 6;
			if (swapped)
				a++;
			break;
		}
		ft = tcc_state->vtop->type.t;
		fc = tcc_state->vtop->c.ul;
		if ((ft & VT_BTYPE) == VT_LDOUBLE) {
			o(tcc_state, 0xde); /* fxxxp %st, %st(1) */
			o(tcc_state, 0xc1 + (a << 3));
		}
		else {
			/* if saved lvalue, then we must reload it */
			r = tcc_state->vtop->r;
			if ((r & VT_VALMASK) == VT_LLOCAL) {
				SValue v1;
				r = get_reg(tcc_state, RC_INT);
				v1.type.t = VT_INT;
				v1.r = VT_LOCAL | VT_LVAL;
				v1.c.ul = fc;
				load(tcc_state, r, &v1);
				fc = 0;
			}

			if ((ft & VT_BTYPE) == VT_DOUBLE)
				o(tcc_state, 0xdc);
			else
				o(tcc_state, 0xd8);
			gen_modrm(tcc_state, a, r, tcc_state->vtop->sym, fc);
		}
		tcc_state->vtop--;
	}
}

/* convert integers to fp 't' type. Must handle 'int', 'unsigned int'
and 'long long' cases. */
ST_FUNC void gen_cvt_itof(TCCState* tcc_state, int t)
{
	save_reg(tcc_state, TREG_ST0);
	gv(tcc_state, RC_INT);
	if ((tcc_state->vtop->type.t & VT_BTYPE) == VT_LLONG) {
		/* signed long long to float/double/long double (unsigned case
		is handled generically) */
		o(tcc_state, 0x50 + tcc_state->vtop->r2); /* push r2 */
		o(tcc_state, 0x50 + (tcc_state->vtop->r & VT_VALMASK)); /* push r */
		o(tcc_state, 0x242cdf); /* fildll (%esp) */
		o(tcc_state, 0x08c483); /* add $8, %esp */
	}
	else if ((tcc_state->vtop->type.t & (VT_BTYPE | VT_UNSIGNED)) ==
		(VT_INT | VT_UNSIGNED)) {
		/* unsigned int to float/double/long double */
		o(tcc_state, 0x6a); /* push $0 */
		g(tcc_state, 0x00);
		o(tcc_state, 0x50 + (tcc_state->vtop->r & VT_VALMASK)); /* push r */
		o(tcc_state, 0x242cdf); /* fildll (%esp) */
		o(tcc_state, 0x08c483); /* add $8, %esp */
	}
	else {
		/* int to float/double/long double */
		o(tcc_state, 0x50 + (tcc_state->vtop->r & VT_VALMASK)); /* push r */
		o(tcc_state, 0x2404db); /* fildl (%esp) */
		o(tcc_state, 0x04c483); /* add $4, %esp */
	}
	tcc_state->vtop->r = TREG_ST0;
}

/* convert fp to int 't' type */
ST_FUNC void gen_cvt_ftoi(TCCState* tcc_state, int t)
{
	int bt = tcc_state->vtop->type.t & VT_BTYPE;
	if (bt == VT_FLOAT)
		vpush_global_sym(tcc_state, &tcc_state->func_old_type, TOK___fixsfdi);
	else if (bt == VT_LDOUBLE)
		vpush_global_sym(tcc_state, &tcc_state->func_old_type, TOK___fixxfdi);
	else
		vpush_global_sym(tcc_state, &tcc_state->func_old_type, TOK___fixdfdi);
	vswap(tcc_state);
	gfunc_call(tcc_state, 1);
	vpushi(tcc_state, 0);
	tcc_state->vtop->r = REG_IRET;
	tcc_state->vtop->r2 = REG_LRET;
}

/* convert from one floating point type to another */
ST_FUNC void gen_cvt_ftof(TCCState* tcc_state, int t)
{
	/* all we have to do on i386 is to put the float in a register */
	gv(tcc_state, RC_FLOAT);
}

/* computed goto support */
ST_FUNC void ggoto(TCCState *tcc_state)
{
	gcall_or_jmp(tcc_state, 1);
	tcc_state->vtop--;
}

/* bound check support functions */
#ifdef CONFIG_TCC_BCHECK

/* generate a bounded pointer addition */
ST_FUNC void gen_bounded_ptr_add(TCCState* tcc_state)
{
	/* prepare fast i386 function call (args in eax and edx) */
	gv2(tcc_state, RC_EAX, RC_EDX);
	/* save all temporary registers */
	tcc_state->vtop -= 2;
	save_regs(tcc_state, 0);
	/* do a fast function call */
	gen_static_call(tcc_state, TOK___bound_ptr_add);
	/* returned pointer is in eax */
	tcc_state->vtop++;
	tcc_state->vtop->r = TREG_EAX | VT_BOUNDED;
	/* address of bounding function call point */
	tcc_state->vtop->c.ul = (tcc_state->cur_text_section->reloc->data_offset - sizeof(Elf32_Rel));
}

/* patch pointer addition in vtop so that pointer dereferencing is
also tested */
ST_FUNC void gen_bounded_ptr_deref(TCCState* tcc_state)
{
	int func;
	int size, align;
	Elf32_Rel *rel;
	Sym *sym;

	size = 0;
	/* XXX: put that code in generic part of tcc */
	if (!is_float(tcc_state->vtop->type.t)) {
		if (tcc_state->vtop->r & VT_LVAL_BYTE)
			size = 1;
		else if (tcc_state->vtop->r & VT_LVAL_SHORT)
			size = 2;
	}
	if (!size)
		size = type_size(&tcc_state->vtop->type, &align);
	switch (size) {
	case  1: func = TOK___bound_ptr_indir1; break;
	case  2: func = TOK___bound_ptr_indir2; break;
	case  4: func = TOK___bound_ptr_indir4; break;
	case  8: func = TOK___bound_ptr_indir8; break;
	case 12: func = TOK___bound_ptr_indir12; break;
	case 16: func = TOK___bound_ptr_indir16; break;
	default:
		tcc_error(tcc_state, "unhandled size when dereferencing bounded pointer");
		func = 0;
		break;
	}

	/* patch relocation */
	/* XXX: find a better solution ? */
	rel = (Elf32_Rel *)(tcc_state->cur_text_section->reloc->data + tcc_state->vtop->c.ul);
	sym = external_global_sym(tcc_state, func, &tcc_state->func_old_type, 0);
	if (!sym->c)
		put_extern_sym(tcc_state, sym, NULL, 0, 0);
	rel->r_info = ELF32_R_INFO(sym->c, ELF32_R_TYPE(rel->r_info));
}
#endif

/* Save the stack pointer onto the stack */
ST_FUNC void gen_vla_sp_save(TCCState *tcc_state, int addr) {
	/* mov %esp,addr(%ebp)*/
	o(tcc_state, 0x89);
	gen_modrm(tcc_state, TREG_ESP, VT_LOCAL, NULL, addr);
}

/* Restore the SP from a location on the stack */
ST_FUNC void gen_vla_sp_restore(TCCState *tcc_state, int addr) {
	o(tcc_state, 0x8b);
	gen_modrm(tcc_state, TREG_ESP, VT_LOCAL, NULL, addr);
}

/* Subtract from the stack pointer, and push the resulting value onto the stack */
ST_FUNC void gen_vla_alloc(TCCState* tcc_state, CType *type, int align) {
#ifdef TCC_TARGET_PE
	/* alloca does more than just adjust %rsp on Windows */
	vpush_global_sym(tcc_state, &tcc_state->func_old_type, TOK_alloca);
	vswap(tcc_state); /* Move alloca ref past allocation size */
	gfunc_call(tcc_state, 1);
	vset(tcc_state, type, REG_IRET, 0);
#else
	int r;
	r = gv(tcc_state, RC_INT); /* allocation size */
	/* sub r,%rsp */
	o(tcc_state, 0x2b);
	o(tcc_state, 0xe0 | r);
	/* We align to 16 bytes rather than align */
	/* and ~15, %esp */
	o(tcc_state, 0xf0e483);
	/* mov %esp, r */
	o(tcc_state, 0x89);
	o(tcc_state, 0xe0 | r);
	vpop(tcc_state);
	vset(tcc_state, type, r, 0);
#endif
}

/* end of X86 code generator */
/*************************************************************/
#endif
/*************************************************************/
