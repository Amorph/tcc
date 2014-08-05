/*
*  GAS like assembler for TCC
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
#ifdef CONFIG_TCC_ASM

ST_FUNC int asm_get_local_label_name(TCCState *tcc_state, unsigned int n)
{
	char buf[64];
	TokenSym *ts;

	snprintf(buf, sizeof(buf), "L..%u", n);
	ts = tok_alloc(tcc_state, buf, strlen(buf));
	return ts->tok;
}

ST_FUNC void asm_expr(TCCState *tcc_state, ExprValue *pe);

/* We do not use the C expression parser to handle symbols. Maybe the
C expression parser could be tweaked to do so. */

static void asm_expr_unary(TCCState *tcc_state, ExprValue *pe)
{
	Sym *sym;
	int op, n, label;
	const char *p;

	switch (tcc_state->tok) {
	case TOK_PPNUM:
		p = tcc_state->tokc.cstr->data;
		n = strtoul(p, (char **)&p, 0);
		if (*p == 'b' || *p == 'f') {
			/* backward or forward label */
			label = asm_get_local_label_name(tcc_state, n);
			sym = label_find(tcc_state, label);
			if (*p == 'b') {
				/* backward : find the last corresponding defined label */
				if (sym && sym->r == 0)
					sym = sym->prev_tok;
				if (!sym)
					tcc_error(tcc_state, "local label '%d' not found backward", n);
			}
			else {
				/* forward */
				if (!sym || sym->r) {
					/* if the last label is defined, then define a new one */
					sym = label_push(tcc_state, &tcc_state->asm_labels, label, 0);
					sym->type.t = VT_STATIC | VT_VOID;
				}
			}
			pe->v = 0;
			pe->sym = sym;
		}
		else if (*p == '\0') {
			pe->v = n;
			pe->sym = NULL;
		}
		else {
			tcc_error(tcc_state, "invalid number syntax");
		}
		next(tcc_state);
		break;
	case '+':
		next(tcc_state);
		asm_expr_unary(tcc_state, pe);
		break;
	case '-':
	case '~':
		op = tcc_state->tok;
		next(tcc_state);
		asm_expr_unary(tcc_state, pe);
		if (pe->sym)
			tcc_error(tcc_state, "invalid operation with label");
		if (op == '-')
			pe->v = -pe->v;
		else
			pe->v = ~pe->v;
		break;
	case TOK_CCHAR:
	case TOK_LCHAR:
		pe->v = tcc_state->tokc.i;
		pe->sym = NULL;
		next(tcc_state);
		break;
	case '(':
		next(tcc_state);
		asm_expr(tcc_state, pe);
		skip(tcc_state, ')');
		break;
	default:
		if (tcc_state->tok >= TOK_IDENT) {
			/* label case : if the label was not found, add one */
			sym = label_find(tcc_state, tcc_state->tok);
			if (!sym) {
				sym = label_push(tcc_state, &tcc_state->asm_labels, tcc_state->tok, 0);
				/* NOTE: by default, the symbol is global */
				sym->type.t = VT_VOID;
			}
			if (sym->r == SHN_ABS) {
				/* if absolute symbol, no need to put a symbol value */
				pe->v = sym->jnext;
				pe->sym = NULL;
			}
			else {
				pe->v = 0;
				pe->sym = sym;
			}
			next(tcc_state);
		}
		else {
			tcc_error(tcc_state, "bad expression syntax [%s]", get_tok_str(tcc_state, tcc_state->tok, &tcc_state->tokc));
		}
		break;
	}
}

static void asm_expr_prod(TCCState *tcc_state, ExprValue *pe)
{
	int op;
	ExprValue e2;

	asm_expr_unary(tcc_state, pe);
	for (;;) {
		op = tcc_state->tok;
		if (op != '*' && op != '/' && op != '%' &&
			op != TOK_SHL && op != TOK_SAR)
			break;
		next(tcc_state);
		asm_expr_unary(tcc_state, &e2);
		if (pe->sym || e2.sym)
			tcc_error(tcc_state, "invalid operation with label");
		switch (op) {
		case '*':
			pe->v *= e2.v;
			break;
		case '/':
			if (e2.v == 0) {
			div_error:
				tcc_error(tcc_state, "division by zero");
			}
			pe->v /= e2.v;
			break;
		case '%':
			if (e2.v == 0)
				goto div_error;
			pe->v %= e2.v;
			break;
		case TOK_SHL:
			pe->v <<= e2.v;
			break;
		default:
		case TOK_SAR:
			pe->v >>= e2.v;
			break;
		}
	}
}

static void asm_expr_logic(TCCState *tcc_state, ExprValue *pe)
{
	int op;
	ExprValue e2;

	asm_expr_prod(tcc_state, pe);
	for (;;) {
		op = tcc_state->tok;
		if (op != '&' && op != '|' && op != '^')
			break;
		next(tcc_state);
		asm_expr_prod(tcc_state, &e2);
		if (pe->sym || e2.sym)
			tcc_error(tcc_state, "invalid operation with label");
		switch (op) {
		case '&':
			pe->v &= e2.v;
			break;
		case '|':
			pe->v |= e2.v;
			break;
		default:
		case '^':
			pe->v ^= e2.v;
			break;
		}
	}
}

static inline void asm_expr_sum(TCCState *tcc_state, ExprValue *pe)
{
	int op;
	ExprValue e2;

	asm_expr_logic(tcc_state, pe);
	for (;;) {
		op = tcc_state->tok;
		if (op != '+' && op != '-')
			break;
		next(tcc_state);
		asm_expr_logic(tcc_state, &e2);
		if (op == '+') {
			if (pe->sym != NULL && e2.sym != NULL)
				goto cannot_relocate;
			pe->v += e2.v;
			if (pe->sym == NULL && e2.sym != NULL)
				pe->sym = e2.sym;
		}
		else {
			pe->v -= e2.v;
			/* NOTE: we are less powerful than gas in that case
			because we store only one symbol in the expression */
			if (!pe->sym && !e2.sym) {
				/* OK */
			}
			else if (pe->sym && !e2.sym) {
				/* OK */
			}
			else if (pe->sym && e2.sym) {
				if (pe->sym == e2.sym) {
					/* OK */
				}
				else if (pe->sym->r == e2.sym->r && pe->sym->r != 0) {
					/* we also accept defined symbols in the same section */
					pe->v += pe->sym->jnext - e2.sym->jnext;
				}
				else {
					goto cannot_relocate;
				}
				pe->sym = NULL; /* same symbols can be subtracted to NULL */
			}
			else {
			cannot_relocate:
				tcc_error(tcc_state, "invalid operation with label");
			}
		}
	}
}

ST_FUNC void asm_expr(TCCState *tcc_state, ExprValue *pe)
{
	asm_expr_sum(tcc_state, pe);
}

ST_FUNC int asm_int_expr(TCCState *tcc_state)
{
	ExprValue e;
	asm_expr(tcc_state, &e);
	if (e.sym)
		expect(tcc_state, "constant");
	return e.v;
}

/* NOTE: the same name space as C labels is used to avoid using too
much memory when storing labels in TokenStrings */
static void asm_new_label1(TCCState *tcc_state, int label, int is_local,
	int sh_num, int value)
{
	Sym *sym;

	sym = label_find(tcc_state, label);
	if (sym) {
		if (sym->r) {
			/* the label is already defined */
			if (!is_local) {
				tcc_error(tcc_state, "assembler label '%s' already defined",
					get_tok_str(tcc_state, label, NULL));
			}
			else {
				/* redefinition of local labels is possible */
				goto new_label;
			}
		}
	}
	else {
	new_label:
		sym = label_push(tcc_state, &tcc_state->asm_labels, label, 0);
		sym->type.t = VT_STATIC | VT_VOID;
	}
	sym->r = sh_num;
	sym->jnext = value;
}

static void asm_new_label(TCCState *tcc_state, int label, int is_local)
{
	asm_new_label1(tcc_state, label, is_local, cur_text_section->sh_num, ind);
}

static void asm_free_labels(TCCState *tcc_state)
{
	Sym *s, *s_prev;
	Section *sec;

	for (s = tcc_state->asm_labels; s != NULL; s = s_prev) {
		s_prev = s->prev;
		/* define symbol value in object file */
		if (s->r) {
			if (s->r == SHN_ABS)
				sec = SECTION_ABS;
			else
				sec = tcc_state->sections[s->r];
			put_extern_sym2(tcc_state, s, sec, s->jnext, 0, 0);
		}
		/* remove label */
		tcc_state->table_ident[s->v - TOK_IDENT]->sym_label = NULL;
		sym_free(tcc_state, s);
	}
	tcc_state->asm_labels = NULL;
}

static void use_section1(TCCState *tcc_state, Section *sec)
{
	cur_text_section->data_offset = ind;
	cur_text_section = sec;
	ind = cur_text_section->data_offset;
}

static void use_section(TCCState *tcc_state, const char *name)
{
	Section *sec;
	sec = find_section(tcc_state, name);
	use_section1(tcc_state, sec);
}

static void asm_parse_directive(TCCState *tcc_state)
{
	int n, offset, v, size, tok1;
	Section *sec;
	uint8_t *ptr;

	/* assembler directive */
	next(tcc_state);
	sec = cur_text_section;
	switch (tcc_state->tok) {
	case TOK_ASM_align:
	case TOK_ASM_skip:
	case TOK_ASM_space:
		tok1 = tcc_state->tok;
		next(tcc_state);
		n = asm_int_expr(tcc_state);
		if (tok1 == TOK_ASM_align) {
			if (n < 0 || (n & (n - 1)) != 0)
				tcc_error(tcc_state, "alignment must be a positive power of two");
			offset = (ind + n - 1) & -n;
			size = offset - ind;
			/* the section must have a compatible alignment */
			if (sec->sh_addralign < n)
				sec->sh_addralign = n;
		}
		else {
			size = n;
		}
		v = 0;
		if (tcc_state->tok == ',') {
			next(tcc_state);
			v = asm_int_expr(tcc_state);
		}
	zero_pad:
		if (sec->sh_type != SHT_NOBITS) {
			sec->data_offset = ind;
			ptr = section_ptr_add(tcc_state, sec, size);
			memset(ptr, v, size);
		}
		ind += size;
		break;
	case TOK_ASM_quad:
		next(tcc_state);
		for (;;) {
			uint64_t vl;
			const char *p;

			p = tcc_state->tokc.cstr->data;
			if (tcc_state->tok != TOK_PPNUM) {
			error_constant:
				tcc_error(tcc_state, "64 bit constant");
			}
			vl = strtoll(p, (char **)&p, 0);
			if (*p != '\0')
				goto error_constant;
			next(tcc_state);
			if (sec->sh_type != SHT_NOBITS) {
				/* XXX: endianness */
				gen_le32(tcc_state, vl);
				gen_le32(tcc_state, vl >> 32);
			}
			else {
				ind += 8;
			}
			if (tcc_state->tok != ',')
				break;
			next(tcc_state);
		}
		break;
	case TOK_ASM_byte:
		size = 1;
		goto asm_data;
	case TOK_ASM_word:
	case TOK_SHORT:
		size = 2;
		goto asm_data;
	case TOK_LONG:
	case TOK_INT:
		size = 4;
	asm_data:
		next(tcc_state);
		for (;;) {
			ExprValue e;
			asm_expr(tcc_state, &e);
			if (sec->sh_type != SHT_NOBITS) {
				if (size == 4) {
					gen_expr32(tcc_state, &e);
				}
				else {
					if (e.sym)
						expect(tcc_state, "constant");
					if (size == 1)
						g(tcc_state, e.v);
					else
						gen_le16(tcc_state, e.v);
				}
			}
			else {
				ind += size;
			}
			if (tcc_state->tok != ',')
				break;
			next(tcc_state);
		}
		break;
	case TOK_ASM_fill:
	{
		int repeat, size, val, i, j;
		uint8_t repeat_buf[8];
		next(tcc_state);
		repeat = asm_int_expr(tcc_state);
		if (repeat < 0) {
			tcc_error(tcc_state, "repeat < 0; .fill ignored");
			break;
		}
		size = 1;
		val = 0;
		if (tcc_state->tok == ',') {
			next(tcc_state);
			size = asm_int_expr(tcc_state);
			if (size < 0) {
				tcc_error(tcc_state, "size < 0; .fill ignored");
				break;
			}
			if (size > 8)
				size = 8;
			if (tcc_state->tok == ',') {
				next(tcc_state);
				val = asm_int_expr(tcc_state);
			}
		}
		/* XXX: endianness */
		repeat_buf[0] = val;
		repeat_buf[1] = val >> 8;
		repeat_buf[2] = val >> 16;
		repeat_buf[3] = val >> 24;
		repeat_buf[4] = 0;
		repeat_buf[5] = 0;
		repeat_buf[6] = 0;
		repeat_buf[7] = 0;
		for (i = 0; i < repeat; i++) {
			for (j = 0; j < size; j++) {
				g(tcc_state, repeat_buf[j]);
			}
		}
	}
		break;
	case TOK_ASM_org:
	{
		unsigned long n;
		next(tcc_state);
		/* XXX: handle section symbols too */
		n = asm_int_expr(tcc_state);
		if (n < ind)
			tcc_error(tcc_state, "attempt to .org backwards");
		v = 0;
		size = n - ind;
		goto zero_pad;
	}
		break;
	case TOK_ASM_globl:
	case TOK_ASM_global:
	case TOK_ASM_weak:
	case TOK_ASM_hidden:
		tok1 = tcc_state->tok;
		do {
			Sym *sym;

			next(tcc_state);
			sym = label_find(tcc_state, tcc_state->tok);
			if (!sym) {
				sym = label_push(tcc_state, &tcc_state->asm_labels, tcc_state->tok, 0);
				sym->type.t = VT_VOID;
			}
			if (tok1 != TOK_ASM_hidden)
				sym->type.t &= ~VT_STATIC;
			if (tok1 == TOK_ASM_weak)
				sym->type.t |= VT_WEAK;
			else if (tok1 == TOK_ASM_hidden)
				sym->type.t |= STV_HIDDEN << VT_VIS_SHIFT;
			next(tcc_state);
		} while (tcc_state->tok == ',');
		break;
	case TOK_ASM_string:
	case TOK_ASM_ascii:
	case TOK_ASM_asciz:
	{
		const uint8_t *p;
		int i, size, t;

		t = tcc_state->tok;
		next(tcc_state);
		for (;;) {
			if (tcc_state->tok != TOK_STR)
				expect(tcc_state, "string constant");
			p = tcc_state->tokc.cstr->data;
			size = tcc_state->tokc.cstr->size;
			if (t == TOK_ASM_ascii && size > 0)
				size--;
			for (i = 0; i < size; i++)
				g(tcc_state, p[i]);
			next(tcc_state);
			if (tcc_state->tok == ',') {
				next(tcc_state);
			}
			else if (tcc_state->tok != TOK_STR) {
				break;
			}
		}
	}
		break;
	case TOK_ASM_text:
	case TOK_ASM_data:
	case TOK_ASM_bss:
	{
		char sname[64];
		tok1 = tcc_state->tok;
		n = 0;
		next(tcc_state);
		if (tcc_state->tok != ';' && tcc_state->tok != TOK_LINEFEED) {
			n = asm_int_expr(tcc_state);
			next(tcc_state);
		}
		sprintf(sname, (n ? ".%s%d" : ".%s"), get_tok_str(tcc_state, tok1, NULL), n);
		use_section(tcc_state, sname);
	}
		break;
	case TOK_ASM_file:
	{
		char filename[512];

		filename[0] = '\0';
		next(tcc_state);

		if (tcc_state->tok == TOK_STR)
			pstrcat(filename, sizeof(filename), tcc_state->tokc.cstr->data);
		else
			pstrcat(filename, sizeof(filename), get_tok_str(tcc_state, tcc_state->tok, NULL));

		if (tcc_state->warn_unsupported)
			tcc_warning(tcc_state, "ignoring .file %s", filename);

		next(tcc_state);
	}
		break;
	case TOK_ASM_ident:
	{
		char ident[256];

		ident[0] = '\0';
		next(tcc_state);

		if (tcc_state->tok == TOK_STR)
			pstrcat(ident, sizeof(ident), tcc_state->tokc.cstr->data);
		else
			pstrcat(ident, sizeof(ident), get_tok_str(tcc_state, tcc_state->tok, NULL));

		if (tcc_state->warn_unsupported)
			tcc_warning(tcc_state, "ignoring .ident %s", ident);

		next(tcc_state);
	}
		break;
	case TOK_ASM_size:
	{
		Sym *sym;

		next(tcc_state);
		sym = label_find(tcc_state, tcc_state->tok);
		if (!sym) {
			tcc_error(tcc_state, "label not found: %s", get_tok_str(tcc_state, tcc_state->tok, NULL));
		}

		/* XXX .size name,label2-label1 */
		if (tcc_state->warn_unsupported)
			tcc_warning(tcc_state, "ignoring .size %s,*", get_tok_str(tcc_state, tcc_state->tok, NULL));

		next(tcc_state);
		skip(tcc_state, ',');
		while (tcc_state->tok != '\n' && tcc_state->tok != CH_EOF) {
			next(tcc_state);
		}
	}
		break;
	case TOK_ASM_type:
	{
		Sym *sym;
		const char *newtype;

		next(tcc_state);
		sym = label_find(tcc_state, tcc_state->tok);
		if (!sym) {
			sym = label_push(tcc_state, &tcc_state->asm_labels, tcc_state->tok, 0);
			sym->type.t = VT_VOID;
		}

		next(tcc_state);
		skip(tcc_state, ',');
		if (tcc_state->tok == TOK_STR) {
			newtype = tcc_state->tokc.cstr->data;
		}
		else {
			if (tcc_state->tok == '@' || tcc_state->tok == '%')
				skip(tcc_state, tcc_state->tok);
			newtype = get_tok_str(tcc_state, tcc_state->tok, NULL);
		}

		if (!strcmp(newtype, "function") || !strcmp(newtype, "STT_FUNC")) {
			sym->type.t = (sym->type.t & ~VT_BTYPE) | VT_FUNC;
		}
		else if (tcc_state->warn_unsupported)
			tcc_warning(tcc_state, "change type of '%s' from 0x%x to '%s' ignored",
			get_tok_str(tcc_state, sym->v, NULL), sym->type.t, newtype);

		next(tcc_state);
	}
		break;
	case TOK_SECTION1:
	{
		char sname[256];

		/* XXX: support more options */
		next(tcc_state);
		sname[0] = '\0';
		while (tcc_state->tok != ';' && tcc_state->tok != TOK_LINEFEED && tcc_state->tok != ',') {
			if (tcc_state->tok == TOK_STR)
				pstrcat(sname, sizeof(sname), tcc_state->tokc.cstr->data);
			else
				pstrcat(sname, sizeof(sname), get_tok_str(tcc_state, tcc_state->tok, NULL));
			next(tcc_state);
		}
		if (tcc_state->tok == ',') {
			/* skip section options */
			next(tcc_state);
			if (tcc_state->tok != TOK_STR)
				expect(tcc_state, "string constant");
			next(tcc_state);
		}
		last_text_section = cur_text_section;
		use_section(tcc_state, sname);
	}
		break;
	case TOK_ASM_previous:
	{
		Section *sec;
		next(tcc_state);
		if (!last_text_section)
			tcc_error(tcc_state, "no previous section referenced");
		sec = cur_text_section;
		use_section1(tcc_state, last_text_section);
		last_text_section = sec;
	}
		break;
#ifdef TCC_TARGET_I386
	case TOK_ASM_code16:
	{
		next(tcc_state);
		tcc_state->seg_size = 16;
	}
		break;
	case TOK_ASM_code32:
	{
		next(tcc_state);
		tcc_state->seg_size = 32;
	}
		break;
#endif
#ifdef TCC_TARGET_X86_64
		/* added for compatibility with GAS */
	case TOK_ASM_code64:
		next(tcc_state);
		break;
#endif
	default:
		tcc_error(tcc_state, "unknown assembler directive '.%s'", get_tok_str(tcc_state, tcc_state->tok, NULL));
		break;
	}
}


/* assemble a file */
static int tcc_assemble_internal(TCCState *tcc_state, int do_preprocess)
{
	int opcode;

#if 0
	/* print stats about opcodes */
	{
		const ASMInstr *pa;
		int freq[4];
		int op_vals[500];
		int nb_op_vals, i, j;

		nb_op_vals = 0;
		memset(freq, 0, sizeof(freq));
		for (pa = asm_instrs; pa->sym != 0; pa++) {
			freq[pa->nb_ops]++;
			for (i = 0; i<pa->nb_ops; i++) {
				for (j = 0; j<nb_op_vals; j++) {
					if (pa->op_type[i] == op_vals[j])
						goto found;
				}
				op_vals[nb_op_vals++] = pa->op_type[i];
			found:;
			}
		}
		for (i = 0; i<nb_op_vals; i++) {
			int v = op_vals[i];
			if ((v & (v - 1)) != 0)
				printf("%3d: %08x\n", i, v);
		}
		printf("size=%d nb=%d f0=%d f1=%d f2=%d f3=%d\n",
			sizeof(asm_instrs), sizeof(asm_instrs) / sizeof(ASMInstr),
			freq[0], freq[1], freq[2], freq[3]);
	}
#endif

	/* XXX: undefine C labels */

	tcc_state->ch = tcc_state->file->buf_ptr[0];
	tcc_state->tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
	tcc_state->parse_flags = PARSE_FLAG_ASM_COMMENTS;
	if (do_preprocess)
		tcc_state->parse_flags |= PARSE_FLAG_PREPROCESS;
	next(tcc_state);
	for (;;) {
		if (tcc_state->tok == TOK_EOF)
			break;
		tcc_state->parse_flags |= PARSE_FLAG_LINEFEED; /* XXX: suppress that hack */
	redo:
		if (tcc_state->tok == '#') {
			/* horrible gas comment */
			while (tcc_state->tok != TOK_LINEFEED)
				next(tcc_state);
		}
		else if (tcc_state->tok == '.') {
			asm_parse_directive(tcc_state);
		}
		else if (tcc_state->tok == TOK_PPNUM) {
			const char *p;
			int n;
			p = tcc_state->tokc.cstr->data;
			n = strtoul(p, (char **)&p, 10);
			if (*p != '\0')
				expect(tcc_state, "':'");
			/* new local label */
			asm_new_label(tcc_state, asm_get_local_label_name(tcc_state, n), 1);
			next(tcc_state);
			skip(tcc_state, ':');
			goto redo;
		}
		else if (tcc_state->tok >= TOK_IDENT) {
			/* instruction or label */
			opcode = tcc_state->tok;
			next(tcc_state);
			if (tcc_state->tok == ':') {
				/* new label */
				asm_new_label(tcc_state, opcode, 0);
				next(tcc_state);
				goto redo;
			}
			else if (tcc_state->tok == '=') {
				int n;
				next(tcc_state);
				n = asm_int_expr(tcc_state);
				asm_new_label1(tcc_state, opcode, 0, SHN_ABS, n);
				goto redo;
			}
			else {
				asm_opcode(tcc_state, opcode);
			}
		}
		/* end of line */
		if (tcc_state->tok != ';' && tcc_state->tok != TOK_LINEFEED){
			expect(tcc_state, "end of line");
		}
		tcc_state->parse_flags &= ~PARSE_FLAG_LINEFEED; /* XXX: suppress that hack */
		next(tcc_state);
	}

	asm_free_labels(tcc_state);

	return 0;
}

/* Assemble the current file */
ST_FUNC int tcc_assemble(TCCState *tcc_state, int do_preprocess)
{
	Sym *define_start;
	int ret;

	preprocess_init(tcc_state);

	/* default section is text */
	cur_text_section = text_section;
	ind = cur_text_section->data_offset;

	define_start = define_stack;

	/* an elf symbol of type STT_FILE must be put so that STB_LOCAL
	symbols can be safely used */
	put_elf_sym(tcc_state, symtab_section, 0, 0,
		ELFW(ST_INFO)(STB_LOCAL, STT_FILE), 0,
		SHN_ABS, tcc_state->file->filename);

	ret = tcc_assemble_internal(tcc_state, do_preprocess);

	cur_text_section->data_offset = ind;

	free_defines(tcc_state, define_start);

	return ret;
}

/********************************************************************/
/* GCC inline asm support */

/* assemble the string 'str' in the current C compilation unit without
C preprocessing. NOTE: str is modified by modifying the '\0' at the
end */
static void tcc_assemble_inline(TCCState *tcc_state, char *str, int len)
{
	int saved_parse_flags;
	const int *saved_macro_ptr;

	saved_parse_flags = tcc_state->parse_flags;
	saved_macro_ptr = tcc_state->macro_ptr;

	tcc_open_bf(tcc_state, ":asm:", len);
	memcpy(tcc_state->file->buffer, str, len);

	tcc_state->macro_ptr = NULL;
	tcc_assemble_internal(tcc_state, 0);
	tcc_close(tcc_state);

	tcc_state->parse_flags = saved_parse_flags;
	tcc_state->macro_ptr = saved_macro_ptr;
}

/* find a constraint by its number or id (gcc 3 extended
syntax). return -1 if not found. Return in *pp in char after the
constraint */
ST_FUNC int find_constraint(TCCState *tcc_state, ASMOperand *operands, int nb_operands,
	const char *name, const char **pp)
{
	int index;
	TokenSym *ts;
	const char *p;

	if (isnum(*name)) {
		index = 0;
		while (isnum(*name)) {
			index = (index * 10) + (*name) - '0';
			name++;
		}
		if ((unsigned)index >= nb_operands)
			index = -1;
	}
	else if (*name == '[') {
		name++;
		p = strchr(name, ']');
		if (p) {
			ts = tok_alloc(tcc_state, name, p - name);
			for (index = 0; index < nb_operands; index++) {
				if (operands[index].id == ts->tok)
					goto found;
			}
			index = -1;
		found:
			name = p + 1;
		}
		else {
			index = -1;
		}
	}
	else {
		index = -1;
	}
	if (pp)
		*pp = name;
	return index;
}

static void subst_asm_operands(TCCState *tcc_state, ASMOperand *operands, int nb_operands,
	int nb_outputs,
	CString *out_str, CString *in_str)
{
	int c, index, modifier;
	const char *str;
	ASMOperand *op;
	SValue sv;

	cstr_new(out_str);
	str = in_str->data;
	for (;;) {
		c = *str++;
		if (c == '%') {
			if (*str == '%') {
				str++;
				goto add_char;
			}
			modifier = 0;
			if (*str == 'c' || *str == 'n' ||
				*str == 'b' || *str == 'w' || *str == 'h')
				modifier = *str++;
			index = find_constraint(tcc_state, operands, nb_operands, str, &str);
			if (index < 0)
				tcc_error(tcc_state, "invalid operand reference after %%");
			op = &operands[index];
			sv = *op->vt;
			if (op->reg >= 0) {
				sv.r = op->reg;
				if ((op->vt->r & VT_VALMASK) == VT_LLOCAL && op->is_memory)
					sv.r |= VT_LVAL;
			}
			subst_asm_operand(tcc_state, out_str, &sv, modifier);
		}
		else {
		add_char:
			cstr_ccat(tcc_state, out_str, c);
			if (c == '\0')
				break;
		}
	}
}


static void parse_asm_operands(TCCState* tcc_state, ASMOperand *operands, int *nb_operands_ptr,
	int is_output)
{
	ASMOperand *op;
	int nb_operands;

	if (tcc_state->tok != ':') {
		nb_operands = *nb_operands_ptr;
		for (;;) {
			if (nb_operands >= MAX_ASM_OPERANDS)
				tcc_error(tcc_state, "too many asm operands");
			op = &operands[nb_operands++];
			op->id = 0;
			if (tcc_state->tok == '[') {
				next(tcc_state);
				if (tcc_state->tok < TOK_IDENT)
					expect(tcc_state, "identifier");
				op->id = tcc_state->tok;
				next(tcc_state);
				skip(tcc_state, ']');
			}
			if (tcc_state->tok != TOK_STR)
				expect(tcc_state, "string constant");
			op->constraint = tcc_malloc(tcc_state, tcc_state->tokc.cstr->size);
			strcpy(op->constraint, tcc_state->tokc.cstr->data);
			next(tcc_state);
			skip(tcc_state, '(');
			gexpr(tcc_state);
			if (is_output) {
				test_lvalue(tcc_state);
			}
			else {
				/* we want to avoid LLOCAL case, except when the 'm'
				constraint is used. Note that it may come from
				register storage, so we need to convert (reg)
				case */
				if ((vtop->r & VT_LVAL) &&
					((vtop->r & VT_VALMASK) == VT_LLOCAL ||
					(vtop->r & VT_VALMASK) < VT_CONST) &&
					!strchr(op->constraint, 'm')) {
					gv(tcc_state, RC_INT);
				}
			}
			op->vt = vtop;
			skip(tcc_state, ')');
			if (tcc_state->tok == ',') {
				next(tcc_state);
			}
			else {
				break;
			}
		}
		*nb_operands_ptr = nb_operands;
	}
}

/* parse the GCC asm() instruction */
ST_FUNC void asm_instr(TCCState *tcc_state)
{
	CString astr, astr1;
	ASMOperand operands[MAX_ASM_OPERANDS];
	int nb_outputs, nb_operands, i, must_subst, out_reg;
	uint8_t clobber_regs[NB_ASM_REGS];

	next(tcc_state);
	/* since we always generate the asm() instruction, we can ignore
	volatile */
	if (tcc_state->tok == TOK_VOLATILE1 || tcc_state->tok == TOK_VOLATILE2 || tcc_state->tok == TOK_VOLATILE3) {
		next(tcc_state);
	}
	parse_asm_str(tcc_state, &astr);
	nb_operands = 0;
	nb_outputs = 0;
	must_subst = 0;
	memset(clobber_regs, 0, sizeof(clobber_regs));
	if (tcc_state->tok == ':') {
		next(tcc_state);
		must_subst = 1;
		/* output args */
		parse_asm_operands(tcc_state, operands, &nb_operands, 1);
		nb_outputs = nb_operands;
		if (tcc_state->tok == ':') {
			next(tcc_state);
			if (tcc_state->tok != ')') {
				/* input args */
				parse_asm_operands(tcc_state, operands, &nb_operands, 0);
				if (tcc_state->tok == ':') {
					/* clobber list */
					/* XXX: handle registers */
					next(tcc_state);
					for (;;) {
						if (tcc_state->tok != TOK_STR)
							expect(tcc_state, "string constant");
						asm_clobber(tcc_state, clobber_regs, tcc_state->tokc.cstr->data);
						next(tcc_state);
						if (tcc_state->tok == ',') {
							next(tcc_state);
						}
						else {
							break;
						}
					}
				}
			}
		}
	}
	skip(tcc_state, ')');
	/* NOTE: we do not eat the ';' so that we can restore the current
	token after the assembler parsing */
	if (tcc_state->tok != ';')
		expect(tcc_state, "';'");

	/* save all values in the memory */
	save_regs(tcc_state, 0);

	/* compute constraints */
	asm_compute_constraints(tcc_state, operands, nb_operands, nb_outputs,
		clobber_regs, &out_reg);

	/* substitute the operands in the asm string. No substitution is
	done if no operands (GCC behaviour) */
#ifdef ASM_DEBUG
	printf("asm: \"%s\"\n", (char *)astr.data);
#endif
	if (must_subst) {
		subst_asm_operands(tcc_state, operands, nb_operands, nb_outputs, &astr1, &astr);
		cstr_free(tcc_state, &astr);
	}
	else {
		astr1 = astr;
	}
#ifdef ASM_DEBUG
	printf("subst_asm: \"%s\"\n", (char *)astr1.data);
#endif

	/* generate loads */
	asm_gen_code(tcc_state, operands, nb_operands, nb_outputs, 0,
		clobber_regs, out_reg);

	/* assemble the string with tcc internal assembler */
	tcc_assemble_inline(tcc_state, astr1.data, astr1.size - 1);

	/* restore the current C token */
	next(tcc_state);

	/* store the output values if needed */
	asm_gen_code(tcc_state, operands, nb_operands, nb_outputs, 1,
		clobber_regs, out_reg);

	/* free everything */
	for (i = 0; i<nb_operands; i++) {
		ASMOperand *op;
		op = &operands[i];
		tcc_free(tcc_state, op->constraint);
		vpop(tcc_state);
	}
	cstr_free(tcc_state, &astr1);
}

ST_FUNC void asm_global_instr(TCCState *tcc_state)
{
	CString astr;

	next(tcc_state);
	parse_asm_str(tcc_state, &astr);
	skip(tcc_state, ')');
	/* NOTE: we do not eat the ';' so that we can restore the current
	token after the assembler parsing */
	if (tcc_state->tok != ';')
		expect(tcc_state, "';'");

#ifdef ASM_DEBUG
	printf("asm_global: \"%s\"\n", (char *)astr.data);
#endif
	cur_text_section = text_section;
	ind = cur_text_section->data_offset;

	/* assemble the string with tcc internal assembler */
	tcc_assemble_inline(tcc_state, astr.data, astr.size - 1);

	cur_text_section->data_offset = ind;

	/* restore the current C token */
	next(tcc_state);

	cstr_free(tcc_state, &astr);
}
#endif /* CONFIG_TCC_ASM */
