## Code execution with a write primitive on last libc.



### 1- Introduction

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

### 1 - Targetting libc GOT entries.

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

### 2 - Targetting ld.so link_map structure.

The prerequisite for this way to achieve code execution, is that the program must exits via `return`, or via `exit()` libc function.

In the two cases, libc will execute `__run_exit_handlers()` function that will call any destructors function registered (also called `dtors`), and will cleanup various things before exiting.

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



------

### 3 - the FSOP way, targetting stdout



(in progress)
