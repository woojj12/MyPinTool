/*BEGIN_LEGAL
Intel Open Source License

Copyright (c) 2002-2013 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/orpw
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
/*
 *  This file contains an ISA-portable PIN tool for tracing system calls
 */

/*
 * /home/jungjae/pin-2.13-61206-gcc.4.4.7-linux/pin -t /home/jungjae/pin-2.13-61206-gcc.4.4.7-linux/source/tools/MyPinTool/obj-intel64/MyPinTool.so -- filebench
 * /home/jungjae/pin-2.13-61206-gcc.4.4.7-linux/pin -follow_execv -t /home/jungjae/pin-2.13-61206-gcc.4.4.7-linux/source/tools/MyPinTool/obj-intel64/MyPinTool.so -- filebench
 *
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

#if defined(TARGET_MAC)
#include <sys/syscall.h>
#elif !defined(TARGET_WINDOWS)
#include <syscall.h>
#endif

#include "pin.H"

/*
 * for malloc
 */
#include <iostream>
#include <fstream>

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif

//linux kernel 3.10
//x86_64 sys call number

//file open/close
#define SYS_OPEN	__NR_open//2
#define SYS_CLOSE	__NR_close//3
#define SYS_PIPE	__NR_pipe	//22
#define SYS_DUP __NR_dup	//32
#define SYS_DUP2	__NR_dup2//33
#define SYS_SOCKET	__NR_socket//41
#define SYS_SOCKETPAIR	__NR_socketpair//53
#define SYS_CREAT	__NR_creat//85
#define SYS_OPENAT	__NR_openat//257
#define SYS_SIGNALFD	__NR_signalfd//282
#define SYS_TIMERFD_CREATE	__NR_timerfd_create//283
#define SYS_EVENTFD	__NR_eventfd//284
#define SYS_SIGNALFD4	__NR_signalfd4//289
#define SYS_DUP3	__NR_dup3//292
#define SYS_PIPE2	__NR_pipe2//293
#define SYS_EVENTFD2	__NR_eventfd2//290
#define SYS_ACCEPT	__NR_accept//43
#define SYS_ACCEPT4	__NR_accept4//288
#define SYS_EPOLL_CREATE	__NR_epoll_create//213
#define SYS_FCNTL	__NR_fcntl//72

#define SYS_READ	__NR_read//0
#define SYS_WRITE	__NR_write//1
#define SYS_STAT	__NR_stat//4
#define SYS_FSTAT	__NR_fstat//5
#define SYS_LSEEK	__NR_lseek//8
#define SYS_MMAP	__NR_mmap//9
#define SYS_MPROTECT	__NR_mprotect//10
#define SYS_MUNMAP	__NR_munmap//11
#define SYS_BRK	__NR_brk//12
#define SYS_PREAD64	__NR_pread64//17
#define SYS_PWRITE64	__NR_pwrite64//18
#define SYS_READV	__NR_readv//19
#define SYS_WRITEV	__NR_writev//20
#define SYS_ACCESS	__NR_access//21
#define SYS_MREMAP	__NR_mremap//25
#define SYS_NANOSLEEP	__NR_nanosleep//35
#define SYS_CLONE	__NR_clone//56
#define SYS_FORK	__NR_fork//57
#define SYS_VFORK	__NR_vfork//58
#define SYS_EXECVE	__NR_execve//59
#define SYS_PREADV	__NR_preadv//295
#define SYS_PWRITEV	__NR_pwritev//296

#define SYS_EXIT	__NR_exit//60
#define SYS_EXIT_GROUP	__NR_exit_group//231
#define SYS_KILL	__NR_kill//62
#define SYS_TKILL	__NR_tkill//200
#define SYS_TGKILL	__NR_tgkill//234

#define SYS_WAIT4	__NR_wait4//247

#define MAX_THREAD 100000
#define MAX_BUFSIZE	1024

#define THREADSTART 1000
#define THREADEND	1001
#define PROCESSEND	1002

#define _MALLOC	2000
#define _FREE	2001
#define MEMORY	2002
#define STACK	2003
#define RETURN	2004

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
int pid;
char *output;

FILE * trace;

PIN_MUTEX lock;

/////////////////////////////////////////////////

struct timeval lt;
static int first = 1;

void set_timer() {

	if (first) {

		gettimeofday(&lt, NULL);

		first = 0;

	}

}

double get_timer() {

	struct timeval tt;

	double lap_time;

	if (first) {

		set_timer();

		return 0.0;

	}

	gettimeofday(&tt, NULL);

	lap_time = (double)(tt.tv_sec - lt.tv_sec) + (double)(tt.tv_usec - lt.tv_usec)/1000000.0;

	return lap_time;
}

struct read
{
	ADDRINT addr;
	ADDRINT size;
	struct read *next;
};
struct read *root_read = NULL;

struct read* InsertRead(ADDRINT addr, ADDRINT size, struct read* node)
{
	struct read* new_node;
	if(node == NULL)
	{
		node = (struct read*)malloc(sizeof(struct read));
		node->addr = addr;
		node->size = size;
		node->next = NULL;
	}
	else if(node->addr == addr)
	{
		if(node->size < size)
		{
			node->size = size;
		}
	}
	else if(node->addr < addr)
	{
		new_node = (struct read*)malloc(sizeof(struct read));
		new_node->addr = addr;
		new_node->size = size;
		new_node->next = node;
		return new_node;
	}
	else
	{
		node->next = InsertRead(addr, size, node->next);
	}
	return node;
}

struct read* FindRead(ADDRINT addr, struct read* node)
{
	if(node == NULL || node->addr > addr)
		return NULL;
	else if(node->addr <= addr && addr <= node->addr + node->size)
	{
		return node;
	}
	else
		return FindRead(addr, node->next);
}

struct thread
{
	PIN_THREAD_UID tid;
	char *buffer;
	int flag;
	ADDRINT mallocsize;
	ADDRINT sp;
	struct thread *left, *right;
	struct read* root_read;
};
struct thread *root_thread;

struct thread* FindThread(PIN_THREAD_UID threadid)
{
	struct thread *t = root_thread;
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

struct thread* FindMin(struct thread *node)
{
	if(node==NULL)
	{
		/* There is no element in the tree */
		return NULL;
	}
	if(node->left) /* Go to the left sub tree to find the min element */
		return FindMin(node->left);
	else
		return node;
}

struct thread* FindMax(struct thread *node)
{
	if(node==NULL)
	{
		/* There is no element in the tree */
		return NULL;
	}
	if(node->right) /* Go to the left sub tree to find the min element */
		return FindMax(node->right);
	else
		return node;
}

struct thread* InsertThread(PIN_THREAD_UID threadid, struct thread *node)
{
	if(node == NULL)
	{
		node = (struct thread*)malloc(sizeof(struct thread));
		assert(node);
		node->tid = threadid;
		node->flag = 0;
		node->left = NULL;
		node->right = NULL;
		node->root_read = NULL;
		node->buffer = (char*)malloc(sizeof(char)*MAX_BUFSIZE);
		assert(node->buffer);
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

struct thread* DeleteThread(PIN_THREAD_UID threadid, struct thread*node)
{
	struct thread *temp;
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
//		free(node->buffer);
		if(node->right && node->left)
		{
			/* Here we will replace with minimum element in the right sub tree */
			temp = FindMin(node->right);
			node -> tid = temp->tid;
			node->buffer = temp->buffer;
			node->flag = temp->flag;

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

struct malloc
{
	ADDRINT addr;
	ADDRINT size;
	struct read *root_read;
	struct malloc *left, *right;
};

VOID MallocBefore(ADDRINT size)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_MutexLock(&lock);
	struct thread *thread = FindThread(threadid);
	PIN_MutexUnlock(&lock);
	thread->mallocsize = size;
}

VOID FreeBefore(ADDRINT size)
{
	if(size != 0)
	fprintf(trace, "%lx %x %lx\n", PIN_ThreadUid(), _FREE, size);
}

VOID MallocAfter(ADDRINT ret)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_MutexLock(&lock);
	struct thread *thread = FindThread(threadid);
	PIN_MutexUnlock(&lock);
	fprintf(trace, "%lx %x %lx %lx\n", threadid, _MALLOC, thread->mallocsize, ret);
}


/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */

VOID Image(IMG img, VOID *v)
{
	// Instrument the malloc() and free() functions.  Print the input argument
	// of each malloc() or free(), and the return value of malloc().
	//
	//  Find the malloc() function.
	RTN mallocRtn = RTN_FindByName(img, MALLOC);
	if (RTN_Valid(mallocRtn))
	{
		RTN_Open(mallocRtn);

		// Instrument malloc() to print the input argument value and the return value.
		RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
				IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

		RTN_Close(mallocRtn);
	}

	// Find the free() function.
	RTN freeRtn = RTN_FindByName(img, FREE);
	if (RTN_Valid(freeRtn))
	{
		RTN_Open(freeRtn);
		// Instrument free() to print the input argument value.
		RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		RTN_Close(freeRtn);
	}
}

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
	//	unsigned int i;
	//	struct iovec* vec;
	//	char buf[MAX_BUFSIZE];

	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_MutexLock(&lock);
	struct thread* thread = FindThread(threadid);
	if(thread ==NULL)
	{
		root_thread = InsertThread(threadid, root_thread);
		thread = FindThread(threadid);
	}
	PIN_MutexUnlock(&lock);

	double stamp;

	switch(num)
	{
	case SYS_READ:
		//arg0 : fd
		//arg1 : buf addr
		//arg2 : buf size

		sprintf(thread->buffer, "%lx %lx %lx %lx %lx ", threadid, num, arg0, arg1, arg2);
		thread->flag = 3;
		root_read = InsertRead(arg1, arg2, root_read);
		return;
	case SYS_WRITE:
		sprintf(thread->buffer, "%lx %lx %lx %lx %lx ", threadid, num, arg0, arg1, arg2);
		thread->flag = 3;
		return;
		//	case SYS_READV:
		//	case SYS_WRITEV:
		//		sprintf(thread->buffer, "%x %lx %lx %lx %lx ", threadid, ip, num, arg0, arg2);
		//		vec = (struct iovec *)arg1;
		//		for(i=0; i < arg2; i++)
		//		{
		//			sprintf(buf, "%lx %lx ", (long int)vec[i].iov_base, (long int)vec[i].iov_len);
		//			strcat(thread->buffer, buf);
		//		}
		//		thread->flag = 3;
		//		return;
		//	case SYS_PREADV:
		//	case SYS_PWRITEV:
		//		sprintf(thread->buffer, "%x %lx %lx %lx %lx %lx", threadid, ip, num, arg0, arg2, arg3);
		//		vec = (struct iovec *)arg1;
		//		for(i=0; i < arg2; i++)
		//		{
		//			sprintf(buf, "%lx %lx ", (long int)vec[i].iov_base, (long int)vec[i].iov_len);
		//			strcat(thread->buffer, buf);
		//		}
		//		thread->flag = 3;
		//		return;
		//
		//	case SYS_PREAD64:
		//	case SYS_PWRITE64:
		//		sprintf(thread->buffer, "%x %lx %lx %lx %lx %lx ", threadid, ip, num, arg0, arg1, arg2);
		//		thread->flag = 3;
		//		return;

	case SYS_LSEEK:
		sprintf(thread->buffer, "%lx %lx %lx %lx %lx ", threadid, num, arg0, arg1, arg2);
		break;

	case SYS_FCNTL:
		if(arg1 == F_DUPFD || arg1 == F_DUPFD_CLOEXEC)
		{
			sprintf(thread->buffer, "%lx %lx %lx ", threadid, num, arg0);
			break;
		}
		else
		{
			thread->flag = 0;
			return;
		}

		//	case SYS_ACCEPT:
		//	case SYS_ACCEPT4:
		//	case SYS_EPOLL_CREATE:
		//	case SYS_SOCKET:
		//	case SYS_DUP:
		//	case SYS_DUP2:
		//	case SYS_DUP3:
		//	case SYS_PIPE:
		//	case SYS_PIPE2:
		//	case SYS_SIGNALFD:
		//	case SYS_TIMERFD_CREATE:
		//	case SYS_EVENTFD:
		//	case SYS_SIGNALFD4:
		//	case SYS_EVENTFD2:
		//		sprintf(thread->buffer, "%x %lx %lx ", threadid, num, arg0);
		//		break;

	case SYS_OPENAT:
		sprintf(thread->buffer, "%lx %lx %s ", threadid, num, (char*)arg1);
		break;

	case SYS_CREAT:
	case SYS_OPEN:
		sprintf(thread->buffer, "%lx %lx %s ", threadid, num, (char*)arg0);
		break;

	case SYS_CLOSE:
		sprintf(thread->buffer, "%lx %lx %lx ", threadid, num, arg0);
		break;

	case SYS_EXIT:
	case SYS_EXIT_GROUP:
	case SYS_FORK:
	case SYS_VFORK:
		fprintf(trace, "%s\n", thread->buffer);
		fflush(trace);
		thread->buffer[0] = '\0';
		thread->flag = 0;
		return;

	case SYS_CLONE:
		sprintf(thread->buffer, "%lx %lx %lx %lx %lx ", threadid, num, arg1, arg2, arg2);
		thread->flag = SYS_CLONE;
		return;

	case SYS_EXECVE:
		stamp = get_timer();

		sprintf(thread->buffer, "%lx %lx %s %lf ", threadid, num, (char*)arg0, stamp);
		fprintf(trace, "%s\n", thread->buffer);
		thread->buffer[0] = '\0';
		fflush(trace);
		thread->flag = 0;
		PIN_MutexLock(&lock);
		root_thread = DeleteThread(threadid, root_thread);
		PIN_MutexUnlock(&lock);
		break;

	default :
		thread->flag = 0;
		return;
	}
	thread->flag = 1;
}

// Print the return value of the system call
VOID SysAfter(ADDRINT ret, ADDRINT num)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_MutexLock(&lock);
	struct thread *thread = FindThread(threadid);
	PIN_MutexUnlock(&lock);
	if(thread->flag != 0)
	{
		if(!(thread->flag == 3 && ((ret+1 == 0) || (ret == 0))))
		{
			char buf[MAX_BUFSIZE];
			double stamp = get_timer();

			sprintf(buf,"%lf %x\n", stamp, (unsigned int)ret);
			strcat(thread->buffer, buf);
			fprintf(trace, "%s", thread->buffer);
			fflush(trace);
			thread->buffer[0] = '\0';
		}
		thread->flag = 0;
	}
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
			PIN_GetSyscallNumber(ctxt, std),
			PIN_GetSyscallArgument(ctxt, std, 0),
			PIN_GetSyscallArgument(ctxt, std, 1),
			PIN_GetSyscallArgument(ctxt, std, 2),
			PIN_GetSyscallArgument(ctxt, std, 3),
			PIN_GetSyscallArgument(ctxt, std, 4),
			PIN_GetSyscallArgument(ctxt, std, 5));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	SysAfter(PIN_GetSyscallReturn(ctxt, std), PIN_GetSyscallNumber(ctxt, std));
}

VOID MemoryRead(ADDRINT ip, ADDRINT memaddr,
		ADDRINT readsize)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
//	if(thread->buffer == NULL)
//	{
//		thread->buffer = (char*)malloc(sizeof(char)*MAX_BUFSIZE);
//	}
	fprintf(trace, "%lx %lx %lx %lx\n", threadid, ip, memaddr, readsize);
	fflush(trace);
}

VOID MemoryWrite(ADDRINT memaddr, ADDRINT writesize)
{
	if(FindRead(memaddr, root_read) != NULL)
	{
		PIN_THREAD_UID threadid = PIN_ThreadUid();
		fprintf(trace, "%lx %x %lx %lx\n", threadid, MEMORY, memaddr, writesize);
	}
//	else
//		fprintf(stderr, "mem null\n");
}
VOID StackWrite(ADDRINT memaddr, ADDRINT writesize)
{
	if(FindRead(memaddr, root_read) != NULL)
	{
		PIN_THREAD_UID threadid = PIN_ThreadUid();
		fprintf(trace, "%lx %x %lx %lx\n", threadid, STACK, memaddr, writesize);
	}
}

VOID Return(ADDRINT sp)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	struct thread* thread = FindThread(threadid);
	fprintf(trace, "%lx %x %lx\n", threadid, RETURN, sp);
}

// Is called for every instruction and instruments syscalls
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
				IARG_END);

		// return value only available after
		INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
				IARG_SYSRET_VALUE,
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
		else if(INS_IsMemoryWrite(ins) && !(INS_IsBranchOrCall(ins)))
		{
			if(INS_IsStackWrite(ins))
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(StackWrite),
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYWRITE_SIZE,
						IARG_END);
			}
			else
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(MemoryWrite),
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYWRITE_SIZE,
						IARG_END);
			}
		}
	}
}

VOID Fini(INT32 code, VOID *v)
{
	fprintf(trace, "%lx %x\n", PIN_ThreadUid(), PROCESSEND);
	fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
	PIN_ERROR("This tool prints a log of system calls"
			+ KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_MutexLock(&lock);
	struct thread *temp = FindThread(threadid);
	if(temp == NULL)
		root_thread = InsertThread(threadid, root_thread);
	PIN_MutexUnlock(&lock);
	fprintf(trace, "%lx %x\n",  threadid, THREADSTART);
	fflush(trace);
}

VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	fprintf(trace, "%lx %x\n", threadid, THREADEND);
	fflush(trace);
	PIN_MutexLock(&lock);
	root_thread = DeleteThread(threadid, root_thread);
	PIN_MutexUnlock(&lock);
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
	// Initialize pin & symbol manager
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) return Usage();

	// Register Image to be called to instrument functions.

	pid = getpid();
	output = (char*)malloc(sizeof(char)*20);
	sprintf(output, "strace%x.out", pid);
	trace = fopen(output, "a");
	free(output);

	char *buf = (char*)malloc(sizeof(char)*200);
	int temp = readlink("/proc/self/exe", buf, 200);
	fprintf(trace, "%s\n", buf);
	free(buf);
	temp = temp+1;

//	fprintf(trace, "%x\n", pid);

	PIN_MutexInit(&lock);
	//
	//	PIN_AddFollowChildProcessFunction(FollowChild, 0);
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	//
	//
	//	// Write to a file since cout and cerr maybe closed by the application
	//	TraceFile.open(KnobOutputFile.Value().c_str());
	//	TraceFile << hex;
	//	TraceFile.setf(ios::showbase);
	//
	IMG_AddInstrumentFunction(Image, 0);
	//
	PIN_AddFiniFunction(Fini, 0);
	//
	set_timer();

	// Never returns
	PIN_StartProgram();

	return 0;
}
