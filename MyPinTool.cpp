/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2013 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

/*! @file
  Generates a trace of malloc/free calls
  @ORIGINAL_AUTHOR: Robert Cohn
 */

#include "pin.H"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <iostream>

/*
 * Define
 */
#define SYS_READ	__NR_read//0
#define SYS_WRITE	__NR_write//1
#define SYS_PREAD64	__NR_pread64//17
#define SYS_PWRITE64	__NR_pwrite64//18
#define SYS_READV	__NR_readv//19
#define SYS_WRITEV	__NR_writev//20
#define SYS_PREADV	__NR_preadv//295
#define SYS_PWRITEV	__NR_pwritev//296

#define MAX_BUFSIZE	1024

/*
 * Data Structure Define
 */
typedef struct treeNode
{
	ADDRINT address;
	ADDRINT size;
	BOOL usedforread;
	ADDRINT offset;

	int fd;
	char *path;
	long int filesize;
	long unsigned int readid;

	struct treeNode *left;
	struct treeNode *right;

}treeNode;

typedef struct thread
{
	PIN_THREAD_UID tid;
	treeNode *stack;

	char buffer[MAX_BUFSIZE];

	struct thread *left, *right;
}THREAD;

/*
 * Function Prototype
 */
INT32 Usage();

VOID ImageLoad(IMG img, VOID *v);
VOID Instruction(INS ins, VOID *v);
VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v);
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v);
VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v);
VOID Fini(INT32 code, VOID *v);

VOID * Malloc( CONTEXT * context, AFUNPTR orgFuncptr, size_t arg0 );
VOID * Realloc( CONTEXT * context, AFUNPTR orgFuncptr, void * ptr, size_t arg0 );
VOID   Free( CONTEXT * context, AFUNPTR orgFuncptr, void * arg0 );

VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT sp);

long unsigned int GetReadId();

THREAD* FindThread(PIN_THREAD_UID threadid);
THREAD* FindMinThread(THREAD *node);
THREAD* FindMaxThread(THREAD *node);
THREAD* InsertThread(PIN_THREAD_UID threadid, THREAD *node);
THREAD* DeleteThread(PIN_THREAD_UID threadid, THREAD *node);

treeNode * InsertDAddress(treeNode *node, ADDRINT address, int fd, ADDRINT size, ADDRINT offset, char* buf, long unsigned int readid);
treeNode * InsertMAddress(treeNode *node, ADDRINT address, ADDRINT size, ADDRINT offset);
treeNode * InsertSAddress(treeNode *node, ADDRINT address, int fd, ADDRINT size, ADDRINT offset, char* buf, long unsigned int readid);
treeNode * FindMinAddress(treeNode *node);
treeNode * FindMaxAddress(treeNode *node);
treeNode * FindAddress(treeNode *node, ADDRINT address);
treeNode * FindAddressInRange(treeNode *node, ADDRINT address);
treeNode * DeleteAddress(treeNode *node, ADDRINT address);
treeNode * DeleteMAddress(treeNode *node, ADDRINT address);

VOID MemoryWrite(ADDRINT memaddr, ADDRINT writesize);
VOID StackWrite(ADDRINT memaddr, ADDRINT writesize);
VOID Return(ADDRINT sp);

/*
 * Global Variable
 */
//Lock
PIN_RWMUTEX thread_lock, malloc_lock, data_lock;
PIN_MUTEX readid_lock;

//BST Root
THREAD *root_thread;
treeNode *malloc_root, *data_root;

FILE *trace;
long unsigned int pagesize;
long unsigned int readid;
int pid;

int main(int argc, CHAR *argv[])
{
    PIN_InitSymbols();

	pagesize = getpagesize();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    //Initialize
    char *buf = (char*)malloc(sizeof(char)*200);
    char *buf2 = (char*)malloc(sizeof(char)*200);
    assert(buf);
    assert(buf2);

    int len = readlink("/proc/self/exe", buf, 200);
    buf[len] = '\0';
    int i;
    for(i=0; i<len; i++)
    {
    	if(buf[i] == '/')
    		buf[i] = '_';
    }
    /*
     * Output log file path
     * Some proccesses change working directory, so output file name should be absolute path
     */
    sprintf(buf2, "/home/jungjae/pin-2.13-61206-gcc.4.4.7-linux/source/tools/MyPinTool/obj-intel64/log");
    strcat(buf2, buf);
    pid = getpid();
    sprintf(buf, "_%x", pid);
    strcat(buf2, buf);

    trace = fopen(buf2, "a");
    assert(trace);
    free(buf);
    free(buf2);
    buf = NULL;
    buf2 = NULL;

    readid = 0;

	PIN_RWMutexInit(&malloc_lock);
	PIN_RWMutexInit(&thread_lock);
	PIN_RWMutexInit(&data_lock);
	PIN_MutexInit(&readid_lock);

	//Add Instrumentation Functions
    IMG_AddInstrumentFunction(ImageLoad, 0);
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);
	PIN_AddFiniFunction(Fini, 0);

	//Program Start. Never Returns
    PIN_StartProgram();

    return 0;
}

/*
 * Instrumented Fuctions
 */

/*
 * ImageLoad
 * Replace native malloc, realloc, free functions with my custum functions
 * so that I can get mem allocation informations.
 */
VOID ImageLoad(IMG img, VOID *v)
{
    RTN mallocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(mallocRtn))
    {
        PROTO proto_malloc = PROTO_Allocate( PIN_PARG(void *), CALLINGSTD_DEFAULT,
                                             "malloc", PIN_PARG(size_t), PIN_PARG_END() );

        RTN_ReplaceSignature(
            mallocRtn, AFUNPTR( Malloc ),
            IARG_PROTOTYPE, proto_malloc,
            IARG_CONTEXT,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_CALL_ORDER, CALL_ORDER_FIRST,
            IARG_END);
    }

    RTN reallocRtn = RTN_FindByName(img, "realloc");
    if (RTN_Valid(reallocRtn))
    {
        PROTO proto_realloc = PROTO_Allocate( PIN_PARG(void *), CALLINGSTD_DEFAULT,
                                             "realloc", PIN_PARG(void *), PIN_PARG(size_t), PIN_PARG_END() );

        RTN_ReplaceSignature(
            reallocRtn, AFUNPTR( Realloc ),
            IARG_PROTOTYPE, proto_realloc,
            IARG_CONTEXT,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_CALL_ORDER, CALL_ORDER_FIRST+1,
            IARG_END);
    }

    RTN freeRtn = RTN_FindByName(img, "free");
    if (RTN_Valid(freeRtn))
    {
        PROTO proto_free = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
                                           "free", PIN_PARG(void *), PIN_PARG_END() );

        RTN_ReplaceSignature(
            freeRtn, AFUNPTR( Free ),
            IARG_PROTOTYPE, proto_free,
            IARG_CONTEXT,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_CALL_ORDER, CALL_ORDER_FIRST+2,
            IARG_END);
    }
}

/*
 * Instruction
 * Catches Syscall, Return, Store functions and calls appropriate handler
 */
VOID Instruction(INS ins, VOID *v)
{
	if (INS_IsSyscall(ins) && INS_HasFallThrough(ins))
	{
		// Arguments and syscall number is only available before
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
				IARG_INST_PTR, IARG_SYSCALL_NUMBER,
				IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
				IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
				IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
				IARG_REG_VALUE, REG_STACK_PTR,
				IARG_END);
	}
	else if (INS_Valid(ins))
	{
		if(INS_IsRet(ins))
		{
			INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(Return),
					IARG_REG_VALUE, REG_STACK_PTR,
					IARG_END);
		}
		else if(INS_IsStackWrite(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(StackWrite),
					IARG_MEMORYWRITE_EA,
					IARG_MEMORYWRITE_SIZE,
					IARG_END);
		}
		else if(INS_IsMemoryWrite(ins) && !(INS_IsBranchOrCall(ins)))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(MemoryWrite),
					IARG_MEMORYWRITE_EA,
					IARG_MEMORYWRITE_SIZE,
					IARG_END);
		}
	}
}

/*
 * SyscallEntry
 * Calls Sysbefore - syscall processor
 */
VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
			PIN_GetSyscallNumber(ctxt, std),
			PIN_GetSyscallArgument(ctxt, std, 0),
			PIN_GetSyscallArgument(ctxt, std, 1),
			PIN_GetSyscallArgument(ctxt, std, 2),
			PIN_GetSyscallArgument(ctxt, std, 3),
			PIN_GetSyscallArgument(ctxt, std, 4),
			PIN_GetSyscallArgument(ctxt, std, 5),
			PIN_GetContextReg(ctxt,REG_STACK_PTR));
}

/*
 * ThreadStart
 * Called when every single thread starts
 * Insert new thread to BST
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_RWMutexWriteLock(&thread_lock);
	root_thread = InsertThread(threadid, root_thread);
	PIN_RWMutexUnlock(&thread_lock);
}

/*
 * ThreadFini
 * Called when every single thread ends
 * Delete the thread from BST
 */
VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_RWMutexWriteLock(&thread_lock);
	root_thread = DeleteThread(threadid, root_thread);
	PIN_RWMutexUnlock(&thread_lock);
}

/*
 * Fini
 * Called when process ends
 * Clean up mems & locks
 */
VOID Fini(INT32 code, VOID *v)
{
	PIN_RWMutexWriteLock(&malloc_lock);
	while(malloc_root != NULL)
		malloc_root = DeleteAddress(malloc_root, malloc_root->address);
	PIN_RWMutexUnlock(&malloc_lock);

	PIN_RWMutexWriteLock(&data_lock);
	while(data_root != NULL)
		data_root = DeleteAddress(data_root, data_root->address);
	PIN_RWMutexUnlock(&data_lock);

	PIN_RWMutexWriteLock(&thread_lock);
	while(root_thread != NULL)
		root_thread = DeleteThread(root_thread->tid, root_thread);
	PIN_RWMutexUnlock(&thread_lock);

	PIN_RWMutexFini(&thread_lock);
	PIN_RWMutexFini(&data_lock);
	PIN_RWMutexFini(&malloc_lock);
	PIN_MutexFini(&readid_lock);

	fclose(trace);
}

/*
 * Replaced Functions
 */
/*
 * Malloc, Realloc
 * Catchs Memory allocations and insert the information to BST
 * Info : Address, Size
 */
VOID * Malloc( CONTEXT * context, AFUNPTR orgFuncptr, size_t size)
{
    VOID * ret;

    PIN_CallApplicationFunction( context, PIN_ThreadId(),
                                 CALLINGSTD_DEFAULT, orgFuncptr,
                                 PIN_PARG(void *), &ret,
                                 PIN_PARG(size_t), size,
                                 PIN_PARG_END() );

	PIN_RWMutexWriteLock(&malloc_lock);
	malloc_root = InsertMAddress(malloc_root, (ADDRINT)ret, size, 0);
	PIN_RWMutexUnlock(&malloc_lock);
    return ret;
}

VOID * Realloc( CONTEXT * context, AFUNPTR orgFuncptr, void * ptr, size_t size)
{
    VOID * ret;

    PIN_CallApplicationFunction( context, PIN_ThreadId(),
                                 CALLINGSTD_DEFAULT, orgFuncptr,
                                 PIN_PARG(void *), &ret,
                                 PIN_PARG(void *), ptr,
                                 PIN_PARG(size_t), size,
                                 PIN_PARG_END() );

	PIN_RWMutexWriteLock(&malloc_lock);
    if(ptr != NULL)
    {
    	if(!FindAddress(malloc_root, (ADDRINT)ret))
    	{
			malloc_root = DeleteMAddress(malloc_root, (ADDRINT)ptr);
			malloc_root = InsertMAddress(malloc_root, (ADDRINT)ret, size, 0);
    	}
    }
	PIN_RWMutexUnlock(&malloc_lock);
    return ret;
}

/*
 * Free
 * Delete Allocation Info from BST
 */
VOID Free( CONTEXT * context, AFUNPTR orgFuncptr, void * ptr)
{
    if(ptr != NULL)
    {
    	if(!FindAddress(malloc_root, (ADDRINT)ptr))
    	{
			PIN_RWMutexWriteLock(&malloc_lock);
			malloc_root = DeleteMAddress(malloc_root, (ADDRINT)ptr);
			PIN_RWMutexUnlock(&malloc_lock);
    	}
    }

    PIN_CallApplicationFunction( context, PIN_ThreadId(),
                                 CALLINGSTD_DEFAULT, orgFuncptr,
                                 PIN_PARG(void),
                                 PIN_PARG(void *), ptr,
                                 PIN_PARG_END() );
}

/*
 * Syscall Processing Function
 */
/*
 * SysBefore
 * Our focus is on "read" syscall, so it traces only read-like syscalls - read, readv, pread, preadv
 */
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT sp)
{

	treeNode *node;
	struct stat stat;
	off_t offset;
	char buf[2][MAX_BUFSIZE];
	int tmp;
	int i;
	long unsigned int readid;
	long unsigned int size;
	struct iovec *vec;

	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_RWMutexReadLock(&thread_lock);
	THREAD* thread = FindThread(threadid);
	PIN_RWMutexUnlock(&thread_lock);
	assert(thread);

	switch(num)
	{
	case SYS_READ:
	case SYS_PREAD64:
		//arg0 : fd
		//arg1 : buf addr
		//arg2 : buf size

		//stdin
		if(arg0 == 0)
			break;

		//Get the path of current file
		sprintf(buf[0], "/proc/self/fd/%d", (int)arg0);
		tmp = readlink(buf[0], buf[1], MAX_BUFSIZE);

		//Skip socket, pipe, proc filesystem, etc
		if(buf[1][0] != '/')
			break;

		if(strncmp(buf[1], "/proc", 5) == 0)
			break;
		else if(strncmp(buf[1], "/dev/urandom", 12)== 0)
			break;

		buf[1][tmp] = '\0';

		if(num == SYS_READ)
		{
			//If SYS_READ, we have to find out current file pointer
			offset = lseek((int)arg0, 0, SEEK_CUR);
			if(offset+1 == 0)
				offset = 0;
		}
		else
		{
			//Or pread case, file pointer is given
			offset = arg3;
		}

		//Get the file size
		size = fstat((int)arg0, &stat);
		assert(size == 0);

		size = stat.st_size;
		if(offset+arg2 > size)
			size = size - offset;
		else
			size = arg2;
		if(size <= 0)
			break;

		//Get Unique ID for each Read
		readid = GetReadId();

		sprintf(thread->buffer, "%s:%lx:%lx:%lx:", buf[1], offset, size, stat.st_size);

		/*
		 * Add Read Info to Data Structure
		 *
		 * Find the buffer address in malloc BST
		 * 	if found, write the info to it
		 *  else
		 *  	Buffer is in stack or data segment
		 */
		PIN_RWMutexReadLock(&malloc_lock);
		node = FindAddressInRange(malloc_root, arg1);
		PIN_RWMutexUnlock(&malloc_lock);
		if(node != NULL)
		{
			node->usedforread = TRUE;
			node->offset = offset;
			node->fd = (int)arg0;
			if(node->path != NULL)
				free(node->path);
			node->path = strdup(buf[1]);
			node->size = size;
			node->readid = readid;
			strcat(thread->buffer, "M");
		}
		else if(arg1 >= sp - pagesize)
		{
			thread->stack = InsertSAddress(thread->stack, arg1, (int)arg0, size, offset, buf[1], readid);
			strcat(thread->buffer, "S");
		}
		else
		{
			PIN_RWMutexWriteLock(&data_lock);
			data_root = InsertDAddress(data_root, arg1, (int)arg0, size, offset, buf[1], readid);
			PIN_RWMutexUnlock(&data_lock);
			strcat(thread->buffer, "D");
		}
		fprintf(trace, "%s\n", thread->buffer);
		fflush(trace);
		break;

	case SYS_PREADV:
	case SYS_READV:
		//arg0 : fd
		//arg1 : iov
		//arg2 : iovcnt
		//iovec.iov_base : address
		//iovec.iov_len : length

		//stdin
		if(arg0 == 0)
			break;

		sprintf(buf[0], "/proc/self/fd/%d", (int)arg0);
		tmp = readlink(buf[0], buf[1], MAX_BUFSIZE);
		if(buf[1][0] != '/')
			break;

		if(strncmp(buf[1], "/proc", 5) == 0)
			break;

		readid = GetReadId();
		buf[1][tmp] = '\0';

		if(num == SYS_READV)
		{
			offset = lseek((int)arg0, 0, SEEK_CUR);
			if(offset+1 == 0)
				offset = 0;
		}
		else
			offset = arg3;

		size = fstat((int)arg0, &stat);
		assert(size == 0);


		vec = (struct iovec *)arg1;
		for(i=0; i < (int)arg2; i++)
		{
			size = stat.st_size;
			if(offset+vec[i].iov_len > size)
				size = size - offset;
			else
				size = vec[i].iov_len;

			if(size <= 0)
				continue;

			PIN_RWMutexReadLock(&malloc_lock);
			node = FindAddressInRange(malloc_root, (ADDRINT)vec[i].iov_base);
			PIN_RWMutexUnlock(&malloc_lock);
			sprintf(thread->buffer, "%s:%lx:%lx:%lx:",buf[1], offset, size, stat.st_size);

			if(node != NULL)
			{
				strcat(thread->buffer, "M");
				node->usedforread = TRUE;
				node->offset = offset;
				node->fd = (int)arg0;
				if(node->path != NULL)
					free(node->path);
				node->path = strdup(buf[1]);
				node->size = size;
				node->readid = readid;
			}
			else if(arg1 >= sp - pagesize)
			{
				strcat(thread->buffer, "S");
				thread->stack = InsertSAddress(thread->stack, arg1, (int)arg0, size, offset, buf[1], readid);
			}
			else
			{
				strcat(thread->buffer, "D");
				PIN_RWMutexWriteLock(&data_lock);
				data_root = InsertDAddress(data_root, arg1, (int)arg0, size, offset, buf[1], readid);
				PIN_RWMutexUnlock(&data_lock);
			}
			fprintf(trace, "%s\n", thread->buffer);
			fflush(trace);
		}
		break;

		/*
	case SYS_WRITE:
	case SYS_PWRITE64:
		if(arg0 == 1 || arg0 == 2)
			break;

		if(num == SYS_WRITE)
		{
			offset = lseek((int)arg0, 0, SEEK_CUR);
			if(offset + 1 == 0)
				offset = 0;
		}
		else
			offset = arg3;

		sprintf(thread->buffer, "%lx:%lx:%lx:%lx:%lx:", num, arg0, arg1, arg2, offset);
		break;

	case SYS_PWRITEV:
	case SYS_WRITEV:
		//stdin
		if(arg0 == 0)
			break;

		sprintf(buf[0], "/proc/self/fd/%d", (int)arg0);
		tmp = readlink(buf[0], buf[1], MAX_BUFSIZE);
		buf[1][tmp] = '\0';

		if(num == SYS_PWRITEV)
		{
			offset = lseek((int)arg0, 0, SEEK_CUR);
			if(offset + 1 == 0)
				offset = 0;
		}
		else
			offset = arg3;

		vec = (struct iovec *)arg1;
		for(i=0; i < (int)arg2; i++)
		{
			sprintf(thread->buffer, "%lx:%lx:%lx:%lx:%lx:", num, arg0, (ADDRINT)vec[i].iov_base, vec[i].iov_len, offset);
		}
		break;
		*/

	default :
		break;
	}
}

/*
 * Return
 * Called when native procedure returns
 * Delete read info of removed stack area
 */
VOID Return(ADDRINT sp)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_RWMutexReadLock(&thread_lock);
	THREAD* thread = FindThread(threadid);
	PIN_RWMutexUnlock(&thread_lock);
	treeNode *node = FindMinAddress(thread->stack);
	if(node == NULL)
		return;
	while(node->address <= sp)
	{
		thread->stack = DeleteAddress(thread->stack, node->address);
		node = FindMinAddress(thread->stack);
		if(node == NULL)
			return;
	}
}

/*
 * MemoryWrite, StackWrite
 * If store occurs and that address was used for read, make a log
 */
VOID MemoryWrite(ADDRINT memaddr, ADDRINT writesize)
{
	treeNode *node;

	ADDRINT startoffset, endoffset;

	PIN_RWMutexReadLock(&data_lock);
	node = FindAddressInRange(data_root, memaddr);
	PIN_RWMutexUnlock(&data_lock);
	if(node && node->usedforread == TRUE)
	{
		startoffset = memaddr - node->address + node->offset;
		endoffset = memaddr - node->address + node->offset + writesize;

		fprintf(trace, "%x%lx:%s:%lx:%lx:D\n", pid, node->readid, node->path, startoffset, endoffset);
		fflush(trace);
		return;
	}
	PIN_RWMutexReadLock(&malloc_lock);
	node = FindAddressInRange(malloc_root, memaddr);
	PIN_RWMutexUnlock(&malloc_lock);
	if(node && node->usedforread == TRUE)
	{
		startoffset = memaddr - node->address + node->offset;
		endoffset = memaddr - node->address + node->offset + writesize;

		fprintf(trace, "%x%lx:%s:%lx:%lx:M\n", pid, node->readid, node->path, startoffset, endoffset);
		fflush(trace);
		return;
	}
}

VOID StackWrite(ADDRINT memaddr, ADDRINT writesize)
{
	treeNode *node;
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	ADDRINT startoffset, endoffset;

	PIN_RWMutexReadLock(&thread_lock);
	THREAD* thread = FindThread(threadid);
	PIN_RWMutexUnlock(&thread_lock);

	node = FindAddressInRange(thread->stack, memaddr);
	if(node && node->usedforread == TRUE)
	{
		startoffset = memaddr - node->address + node->offset;
		endoffset = memaddr - node->address + node->offset + writesize;

		fprintf(trace, "%x%lx:%s:%lx:%lx:S\n", pid, node->readid, node->path, startoffset, endoffset);
		fflush(trace);
	}
}


/*
 * GetReadId
 * Returns the unique read id
 */
long unsigned int GetReadId()
{
	long unsigned int ret;

	PIN_MutexLock(&readid_lock);
	ret = readid;
	readid++;
	PIN_MutexUnlock(&readid_lock);

	return ret;
}

/*
 * BST Functions
 */
treeNode* FindMinAddress(treeNode *node)
{
	if(node==NULL)
	{
		/* There is no element in the tree */
		return NULL;
	}
	if(node->left) /* Go to the left sub tree to find the min element */
		return FindMinAddress(node->left);
	else
		return node;
}

treeNode* FindMaxAddress(treeNode *node)
{
	if(node==NULL)
	{
		/* There is no element in the tree */
		return NULL;
	}
	if(node->right) /* Go to the left sub tree to find the min element */
		return FindMaxAddress(node->right);
	else
		return node;
}

treeNode * InsertDAddress(treeNode *node, ADDRINT address, int fd, ADDRINT size, ADDRINT offset, char* buf, long unsigned int readid)
{
	if(node==NULL)
	{
		treeNode *temp;
		temp = (treeNode *)malloc(sizeof(treeNode));
		assert(temp);
		temp -> address = address;
		temp -> size = size;
		temp -> usedforread = TRUE;
		temp -> left = temp -> right = NULL;
		temp->offset = offset;
		temp->fd = fd;
		temp->path = strdup(buf);
		temp->readid = readid;
		return temp;
	}

	if(address >(node->address))
	{
		node->right = InsertDAddress(node->right,address,fd,size, offset, buf, readid);
	}
	else if(address < (node->address))
	{
		node->left = InsertDAddress(node->left,address,fd,size, offset, buf, readid);
	}
	else
	{
		node->size = size;
		node->offset = offset;
		node->usedforread = TRUE;
		node->readid = readid;
		if(node->path != NULL)
			free(node->path);
		node->path = strdup(buf);
	}
	/* Else there is nothing to do as the data is already in the tree. */
	return node;
}

treeNode * InsertSAddress(treeNode *node, ADDRINT address, int fd, ADDRINT size, ADDRINT offset, char* buf, long unsigned int readid)
{
	if(node==NULL)
	{
		treeNode *temp;
		temp = (treeNode *)malloc(sizeof(treeNode));
		assert(temp);
		temp -> address = address;
		temp -> size = size;
		temp -> usedforread = TRUE;
		temp->offset = offset;
		temp -> left = temp -> right = NULL;
		temp->fd = fd;
		temp->path = strdup(buf);
		temp->readid = readid;
		return temp;
	}

	if(address >(node->address))
	{
		node->right = InsertSAddress(node->right,address,fd,size, offset, buf, readid);
	}
	else if(address < (node->address))
	{
		node->left = InsertSAddress(node->left,address,fd,size, offset, buf, readid);
	}
	else
	{
		node->fd = fd;
		node->size = size;
		node->offset = offset;
		node->usedforread = TRUE;
		node->readid = readid;
		if(node->path != NULL)
			free(node->path);
		node->path = strdup(buf);
	}
	/* Else there is nothing to do as the data is already in the tree. */
	return node;
}

treeNode * InsertMAddress(treeNode *node, ADDRINT address, ADDRINT size, ADDRINT offset)
{
	if(node==NULL)
	{
		treeNode *temp;
		temp = (treeNode *)malloc(sizeof(treeNode));
		assert(temp);
		temp -> address = address;
		temp->offset = offset;
		temp -> size = size;
		temp -> usedforread = FALSE;
		temp -> left = temp -> right = NULL;
		temp->path = NULL;
		return temp;
	}

	if(address >(node->address))
	{
		node->right = InsertMAddress(node->right,address,size, offset);
	}
	else if(address < (node->address))
	{
		node->left = InsertMAddress(node->left,address,size, offset);
	}
	else
	{
		node->size = size;
		node->address = address;
		node->usedforread = FALSE;
		if(node->path != NULL)
			free(node->path);
		node->path = NULL;
	}
	/* Else there is nothing to do as the data is already in the tree. */
	return node;
}

treeNode * DeleteAddress(treeNode *node, ADDRINT address)
{
	treeNode *temp;
	if(node == NULL)
	{
//		assert(0);
		return NULL;
	}
	if(address < node->address)
	{
		node->left = DeleteAddress(node->left, address);
	}
	else if(address > node->address)
	{
		node->right = DeleteAddress(node->right, address);
	}
	else
	{
		/* Now We can delete this node and replace with either minimum element
                   in the right sub tree or maximum element in the left subtree */
		if(node->right && node->left)
		{
			/* Here we will replace with minimum element in the right sub tree */
			temp = FindMinAddress(node->right);
			node -> address = temp->address;
			node->size = temp->size;
			node->usedforread = temp->usedforread;
			if(node->path != NULL)
				free(node->path);
			node->path = temp->path;
			temp->path = NULL;
			node->readid = temp->readid;

			/* As we replaced it with some other node, we have to delete that node */
			node -> right = DeleteAddress(node->right,temp->address);
		}
		else
		{
			/* If there is only one or zero children then we can directly
                           remove it from the tree and connect its parent to its child */
			temp = node;
			if(node->left == NULL)
				node = node->right;
			else if(node->right == NULL)
				node = node->left;
			else
				assert(0);
			if(temp->path != NULL)
				free(temp->path);
			free(temp); /* temp is longer required */
		}
	}
	return node;
}

treeNode * DeleteMAddress(treeNode *node, ADDRINT address)
{
	treeNode *temp;
	if(node == NULL)
	{
//		assert(0);
		return NULL;
	}
	if(address < node->address)
	{
		node->left = DeleteMAddress(node->left, address);
	}
	else if(address > node->address)
	{
		node->right = DeleteMAddress(node->right, address);
	}
	else
	{
		/* Now We can delete this node and replace with either minimum element
                   in the right sub tree or maximum element in the left subtree */
		if(node->right && node->left)
		{
			/* Here we will replace with minimum element in the right sub tree */
			temp = FindMinAddress(node->right);
			node -> address = temp->address;
			node->size = temp->size;
			node->usedforread = temp->usedforread;
			node->readid = temp->readid;
			if(node->path != NULL)
				free(node->path);
			node->path = temp->path;
			temp->path = NULL;

			/* As we replaced it with some other node, we have to delete that node */
			node -> right = DeleteMAddress(node->right,temp->address);
		}
		else
		{
			/* If there is only one or zero children then we can directly
                           remove it from the tree and connect its parent to its child */
			temp = node;
			if(node->left == NULL)
				node = node->right;
			else if(node->right == NULL)
				node = node->left;
			else
				assert(0);
			free(temp); /* temp is longer required */
		}
	}
	return node;
}

treeNode * FindAddress(treeNode *node, ADDRINT address)
{
	if(node==NULL)
	{
		/* Element is not found */
		return NULL;
	}
	if(address > node->address)
	{
		/* Search in the right sub tree. */
		return FindAddress(node->right,address);
	}
	else if(address < node->address)
	{
		/* Search in the left sub tree. */
		return FindAddress(node->left,address);
	}
	else
	{
		/* Element Found */
		return node;
	}
}

treeNode* FindAddressInRange(treeNode *node, ADDRINT address)
{
	if(node==NULL)
	{
		/* Element is not found */
		return NULL;
	}
	if(address > node->address + node->size - 1)
	{
		/* target node. */
		return FindAddressInRange(node->right,address);
	}
	else if(address >= node->address)
	{
		/* Search in the right sub tree. */
		return node;
	}
	else
	{
		/* Search in the left sub tree. */
		return FindAddressInRange(node->left,address);
	}
}

/* ===================================================================== */

INT32 Usage()
{
    cerr <<
        "This pin tool collects an instruction trace for debugging\n"
        "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}

///////////////////////////////////////////////////////////////////

THREAD* FindThread(PIN_THREAD_UID threadid)
{
	THREAD *t = root_thread;
	while(t != NULL)
	{
		if(t->tid == threadid)
			return t;
		else if(t->tid > threadid)
			t = t->left;
		else
			t = t->right;
	}
	return NULL;
}

THREAD* FindMinThread(THREAD *node)
{
	if(node==NULL)
	{
		/* There is no element in the tree */
		return NULL;
	}
	if(node->left) /* Go to the left sub tree to find the min element */
		return FindMinThread(node->left);
	else
		return node;
}

THREAD* FindMaxThread(THREAD *node)
{
	if(node==NULL)
	{
		/* There is no element in the tree */
		return NULL;
	}
	if(node->right) /* Go to the left sub tree to find the min element */
		return FindMaxThread(node->right);
	else
		return node;
}

THREAD* InsertThread(PIN_THREAD_UID threadid, THREAD *node)
{
	if(node == NULL)
	{
		node = (THREAD*)malloc(sizeof(THREAD));
		assert(node);
		node->tid = threadid;
		node->left = NULL;
		node->right = NULL;
		node->stack = NULL;
	}
	else
	{
		if(node->tid < threadid)
			node->right = InsertThread(threadid, node->right);
		else if(node->tid < threadid)
			node->left = InsertThread(threadid, node->left);
		else
		{
			fprintf(stderr, "err %lx\n", threadid);
			assert(0);
		}
	}
	return node;
}

THREAD* DeleteThread(PIN_THREAD_UID threadid, THREAD*node)
{
	THREAD *temp;
	assert(node);
	if(threadid < node->tid)
	{
		node->left = DeleteThread(threadid, node->left);
	}
	else if(threadid > node->tid)
	{
		node->right = DeleteThread(threadid, node->right);
	}
	else
	{
		/* Now We can delete this node and replace with either minimum element
                   in the right sub tree or maximum element in the left subtree */
		while(node->stack != NULL)
			node->stack = DeleteAddress(node->stack, node->stack->address);
		if(node->right && node->left)
		{
			/* Here we will replace with minimum element in the right sub tree */
			temp = FindMinThread(node->right);
			node -> tid = temp->tid;
			node->stack = temp->stack;

			/* As we replaced it with some other node, we have to delete that node */
			node -> right = DeleteThread(temp->tid, node->right);
		}
		else
		{
			/* If there is only one or zero children then we can directly
                           remove it from the tree and connect its parent to its child */
			temp = node;
			if(node->left == NULL)
				node = node->right;
			else if(node->right == NULL)
				node = node->left;
			free(temp); /* temp is longer required */
		}
	}
	return node;
}
