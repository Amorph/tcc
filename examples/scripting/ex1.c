#include "tcc.h"
#include "libtcc.h"

typedef void (*err_func_t)(void* opaque, const char* msg);

const char* script = "\n"
	"	typedef void (*err_func_t)(void* opaque, const char* msg);	\n"
	"	int script_main(int arg, err_func_t error)					\n"
	"	{															\n"
	"		error(arg * 2, \"Hello world\");						\n"
	"		return arg * 2;											\n"
	"	}															\n";

const char* script2 = "\n"
	"	typedef void (*err_func_t)(void* opaque, const char* msg);	\n"
	"	int script_main2(int arg, err_func_t error)					\n"
	"	{															\n"
	"		return script_main2(arg * 2, error);					\n"
	"	}															\n";


typedef int (*script_func)(int, void*);

void err_func(void* opaque, const char* msg)
{
};

int main(int argc, char** argv)
{
	int res;
	script_func f;
	TCCState* S = tcc_new();
	S->error_func = err_func;
	S->nostdlib = 1;
	tcc_compile_string(S, script);

	if (tcc_relocate(S, TCC_RELOCATE_AUTO) < 0)
		return -1;

	tcc_compile_string(S, script2);

	tcc_relocate(S, TCC_RELOCATE_AUTO);
	//	return -1;
	
	f = (script_func)tcc_get_symbol(S, "script_main2");
	res = f(10,err_func);

	return 0;
}