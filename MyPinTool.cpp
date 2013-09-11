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
/*
 *  This file contains an ISA-portable PIN tool for tracing system calls
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
#define SYS_OPEN	2
#define SYS_CLOSE	3
#define SYS_PIPE	22
#define SYS_DUP	32
#define SYS_DUP2	33
#define SYS_SOCKET	41
#define SYS_SOCKETPAIR	53
#define SYS_CREAT	85
#define SYS_OPENAT	257
#define SYS_SIGNALFD	282
#define SYS_TIMERFD_CREATE	283
#define SYS_EVENTFD	284
#define SYS_SIGNALFD4	289
#define SYS_DUP3	292
#define SYS_PIPE2	293
#define SYS_EVENTFD2	290
#define SYS_ACCEPT	43
#define SYS_ACCEPT4	288
#define SYS_EPOLL_CREATE	213
#define SYS_FCNTL	72

#define SYS_READ	0
#define SYS_WRITE	1
#define SYS_STAT	4
#define SYS_FSTAT	5
#define SYS_LSEEK	8
#define SYS_MMAP	9
#define SYS_MPROTECT	10
#define SYS_MUNMAP	11
#define SYS_BRK	12
#define SYS_RT_SIGACTION	13
#define SYS_RT_SIGPROCMASK	14
#define SYS_RT_SIG_RETURN	15
#define SYS_PREAD64	17
#define SYS_PWRITE64	18
#define SYS_READV	19
#define SYS_WRITEV	20
#define SYS_ACCESS	21
#define SYS_MREMAP	25
#define SYS_NANOSLEEP	35
#define SYS_CLONE	56
#define SYS_FORK	57
#define SYS_VFORK	58
#define SYS_EXECVE	59
#define SYS_GETRLIMIT	97
#define SYS_GETPRIORITY	140
#define SYS_SETPRIORITY	141
#define SYS_ARCH_PRCTL	158
#define SYS_SETRLIMIT	160
#define SYS_GETTID	186
#define SYS_FUTEX	202
#define SYS_SET_TID_ADDRESS	218
#define SYS_SET_ROBUST_LIST 273
#define SYS_PREADV	295
#define SYS_PWRITEV	296

#define SYS_EXIT	60
#define SYS_EXIT_GROUP	231
#define SYS_KILL	62
#define SYS_TKILL	200
#define SYS_TGKILL	234

#define SYS_WAIT4	247

#define MAX_THREAD 100000
#define MAX_BUFSIZE	1024

#define PROCESSEND	9999
#define THREADEND	999

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
int pid;
char *output;

FILE * trace;
int flag[MAX_THREAD];
char* per_thread_buf[2][MAX_THREAD];

std::ofstream TraceFile;

typedef struct log
{
	long unsigned int address;
	long unsigned int size;

	double time;

	BOOL isread;

	struct log* next;
} log;

typedef struct treeNode
{
	long unsigned int address;
	long unsigned int size;
	BOOL usedforread;

	struct log *log;

	struct treeNode *left;
	struct treeNode *right;

}treeNode;

treeNode *bst_root;

VOID InsertLog(treeNode *node, log* log)
{
	log->next = node->log;
	node->log = log;
}


treeNode* FindMin(treeNode *node)
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
treeNode* FindMax(treeNode *node)
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

treeNode * Insert(treeNode *node, long unsigned int address, long unsigned int size)
{
	if(node==NULL)
	{
		treeNode *temp;
		temp = (treeNode *)malloc(sizeof(treeNode));
		temp -> address = address;
		temp -> size = size;
		temp -> usedforread = FALSE;
		temp -> log = NULL;
		temp -> left = temp -> right = NULL;
		return temp;
	}

	if(address >(node->address))
	{
		node->right = Insert(node->right,address,size);
	}
	else if(address < (node->address))
	{
		node->left = Insert(node->left,address,size);
	}
	/* Else there is nothing to do as the data is already in the tree. */
	return node;
}

struct log* FreeLog(struct log* log)
{
	if(log != NULL)
	{
		log->next = FreeLog(log->next);
		free(log);
		return NULL;
	}
	else
		return NULL;
}

int PrintLog(struct log *log)
{
	int ret;
	if(log == NULL)
		return 0;

	ret = PrintLog(log->next);
	if(log->isread == TRUE)
	{
		fprintf(trace, "read %lx %lx\n", log->address, log->size);
		return 1;
	}
	else if(ret != 0)
	{
		fprintf(trace, "store %lx %lx\n", log->address, log->size);
		return 1;
	}
	else
	{
		return 0;
	}
}

treeNode * Delete(treeNode *node, long unsigned int address)
{
	treeNode *temp;
	assert(node != NULL);

	if(address < node->address)
	{
		node->left = Delete(node->left, address);
	}
	else if(address > node->address)
	{
		node->right = Delete(node->right, address);
	}
	else
	{
		if(node->usedforread == TRUE)
		{
//			assert(0);
			assert(node->log != NULL);
			PrintLog(node->log);
		}
		node->log = FreeLog(node->log);
		/* Now We can delete this node and replace with either minimum element
                   in the right sub tree or maximum element in the left subtree */
		if(node->right && node->left)
		{
			/* Here we will replace with minimum element in the right sub tree */
			temp = FindMin(node->right);
			node -> address = temp->address;
			node->size = temp->size;
			node->log = temp->log;

			/* As we replaced it with some other node, we have to delete that node */
			node -> right = Delete(node->right,temp->address);
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

treeNode * Find(treeNode *node, long unsigned int address)
{
	if(node==NULL)
	{
		/* Element is not found */
		return NULL;
	}
	if(address > node->address)
	{
		/* Search in the right sub tree. */
		return Find(node->right,address);
	}
	else if(address < node->address)
	{
		/* Search in the left sub tree. */
		return Find(node->left,address);
	}
	else
	{
		/* Element Found */
		return node;
	}
}

treeNode* FindInRange(treeNode *node, long unsigned int address)
{
	if(node==NULL)
	{
		/* Element is not found */
		return NULL;
	}
	if(address > node->address + node->size)
	{
		/* target node. */
		return FindInRange(node->right,address);
	}
	if(address >= node->address)
	{
		/* Search in the right sub tree. */
		return node;
	}
	else
	{
		/* Search in the left sub tree. */
		return FindInRange(node->left,address);
	}
}

VOID PrintInorder(treeNode *node)
{
	if(node==NULL)
	{
		return;
	}
	PrintInorder(node->left);
	printf("%ld ",node->address);
	PrintInorder(node->right);
}

VOID PrintPreorder(treeNode *node)
{
	if(node==NULL)
	{
		return;
	}
	printf("%ld ",node->address);
	PrintPreorder(node->left);
	PrintPreorder(node->right);
}

VOID PrintPostorder(treeNode *node)
{
	if(node==NULL)
	{
		return;
	}
	PrintPostorder(node->left);
	PrintPostorder(node->right);
	printf("%ld ",node->address);
}

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
		"o", "malloctrace.ooo", "specify trace file name");

/* ===================================================================== */

long unsigned int mallocsize[MAX_THREAD];

/* ===================================================================== */
/* Analysis routines                                                     */
/* ===================================================================== */

VOID Arg1Before(CHAR * name, ADDRINT size)
{
	int threadid = PIN_GetTid();
	if(name[0] == 'm')
	{
//		if(per_thread_buf[1][threadid] == NULL)
//		{
//			per_thread_buf[1][threadid] = (char*)malloc(sizeof(char)*MAX_BUFSIZE);
//		}
//		sprintf(per_thread_buf[1][threadid], "%s %lx ", name, size);
		mallocsize[threadid] = size;
	}
	else
	{
//		TraceFile << name << "(" << size << ")" << endl;
//		fprintf(trace, "%s %lx\n", name, size);
		if(size != 0)
			bst_root = Delete(bst_root, (long unsigned int)size);
	}
}

VOID MallocAfter(ADDRINT ret)
{
	int threadid = PIN_GetTid();
	bst_root = Insert(bst_root, ret, mallocsize[threadid]);
//	assert(per_thread_buf[1][threadid]);
//	fprintf(trace, "%s", per_thread_buf[1][threadid]);
//	fprintf(trace, "%lx\n", ret);
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
		RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
				IARG_ADDRINT, MALLOC,
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
		RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)Arg1Before,
				IARG_ADDRINT, FREE,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		RTN_Close(freeRtn);
	}
}

/* ===================================================================== */


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

struct thread
{
	THREADID tid;
	struct thread *parent;
	struct thread_list *children;
	struct fd_list *fd_own;
	struct fd_list *fd_inherit;
};
struct thread *root_thread;

struct thread_list
{
	struct thread *thread;
	struct thread_list *next;
};

struct fd_list
{
	int fd;
	struct fd_list *next;
};

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{
//	unsigned int i;
//	struct iovec* vec;
//	char buf[MAX_BUFSIZE];

	int threadid = PIN_GetTid();
	if(per_thread_buf[0][threadid] == NULL)
	{
		per_thread_buf[0][threadid] = (char*)malloc(sizeof(char)*MAX_BUFSIZE);
	}
	double stamp;
	treeNode *node;
	log *log;

	switch(num)
	{
	case SYS_READ:
		node = FindInRange(bst_root, arg1);
		if(node != NULL)
		{
//			assert(0);
			log = (struct log*)malloc(sizeof(struct log));
			log->time = get_timer();
			log->address = arg1;
			log->size = arg2;
			log->isread = TRUE;
			InsertLog(node, log);
			node->usedforread = TRUE;
		}
		else
		{
			fprintf(trace, "read at non malloced %.6lf %lx %lx\n", get_timer(), arg1, arg2);
		}

		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %lx %lx %lx ", threadid, ip, num, arg0, arg1, arg2);
		flag[threadid] = 3;
		return;
	case SYS_WRITE:
		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %lx %lx %lx ", threadid, ip, num, arg0, arg1, arg2);
		flag[threadid] = 3;
		return;
//	case SYS_READV:
//	case SYS_WRITEV:
//		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %lx %lx ", threadid, ip, num, arg0, arg2);
//		vec = (struct iovec *)arg1;
//		for(i=0; i < arg2; i++)
//		{
//			sprintf(buf, "%lx %lx ", (long int)vec[i].iov_base, (long int)vec[i].iov_len);
//			strcat(per_thread_buf[0][threadid], buf);
//		}
//		flag[threadid] = 3;
//		return;
//	case SYS_PREADV:
//	case SYS_PWRITEV:
//		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %lx %lx %lx", threadid, ip, num, arg0, arg2, arg3);
//		vec = (struct iovec *)arg1;
//		for(i=0; i < arg2; i++)
//		{
//			sprintf(buf, "%lx %lx ", (long int)vec[i].iov_base, (long int)vec[i].iov_len);
//			strcat(per_thread_buf[0][threadid], buf);
//		}
//		flag[threadid] = 3;
//		return;
//
//	case SYS_PREAD64:
//	case SYS_PWRITE64:
//		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %lx %lx %lx ", threadid, ip, num, arg0, arg1, arg2);
//		flag[threadid] = 3;
//		return;

	case SYS_LSEEK:
		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %lx %lx %lx ", threadid, ip, num, arg0, arg1, arg2);
		break;

	case SYS_FCNTL:
		if(arg1 == F_DUPFD || arg1 == F_DUPFD_CLOEXEC)
		{
			sprintf(per_thread_buf[0][threadid], "%x %lx %lx %lx ", threadid, ip, num, arg0);
			break;
		}
		else
		{
			flag[threadid] = 0;
			return;
		}

	case SYS_ACCEPT:
	case SYS_ACCEPT4:
	case SYS_EPOLL_CREATE:
	case SYS_SOCKET:
	case SYS_DUP:
	case SYS_DUP2:
	case SYS_DUP3:
	case SYS_PIPE:
	case SYS_PIPE2:
	case SYS_SIGNALFD:
	case SYS_TIMERFD_CREATE:
	case SYS_EVENTFD:
	case SYS_SIGNALFD4:
	case SYS_EVENTFD2:
		sprintf(per_thread_buf[0][threadid], "%x %lx %lx ", threadid, ip, num);
		break;

	case SYS_OPENAT:
		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %s ", threadid, ip, num, (char*)arg1);
		break;

	case SYS_CREAT:
	case SYS_OPEN:
		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %s ", threadid, ip, num, (char*)arg0);
		break;

	case SYS_CLOSE:
		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %lx ", threadid, ip, num, arg0);
		break;

	case SYS_EXIT:
	case SYS_EXIT_GROUP:
	case SYS_FORK:
	case SYS_VFORK:
		fprintf(trace, "%s\n", per_thread_buf[0][threadid]);
		fflush(trace);
		per_thread_buf[0][threadid][0] = '\0';
		flag[threadid] = 0;
		return;

	case SYS_CLONE:
		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %lx %lx %lx ", threadid, ip, num, arg1, arg2, arg2);
		flag[threadid] = SYS_CLONE;
		return;

	case SYS_EXECVE:
		stamp = get_timer();

		sprintf(per_thread_buf[0][threadid], "%x %lx %lx %s %lf ", threadid, ip, num, (char*)arg0, stamp);
		fprintf(trace, "%s\n", per_thread_buf[0][threadid]);
		fflush(trace);
		flag[threadid] = SYS_EXECVE;
		break;

	default :
		flag[threadid] = 0;
		return;
	}
	flag[threadid] = 1;
}

// Print the return value of the system call
VOID SysAfter(ADDRINT ret, ADDRINT num)
{
	int threadid = PIN_GetTid();
	if(flag[threadid] != 0)
	{
		if(!(flag[threadid] == 3 && ((ret+1 == 0) || (ret == 0))))
		{
			char buf[MAX_BUFSIZE];
			double stamp = get_timer();

			sprintf(buf,"%lf %x\n", stamp, (unsigned int)ret);
			strcat(per_thread_buf[0][threadid], buf);
			fprintf(trace, "%s", per_thread_buf[0][threadid]);
			fflush(trace);
			per_thread_buf[0][threadid][0] = '\0';
		}
	}
	flag[threadid] = 0;
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
	int threadid = PIN_GetTid();
	if(per_thread_buf[0][threadid] == NULL)
	{
		per_thread_buf[0][threadid] = (char*)malloc(sizeof(char)*MAX_BUFSIZE);
	}
	fprintf(trace, "%x %lx %lx %lx\n", threadid, ip, memaddr, readsize);
	fflush(trace);
}

VOID MemoryWrite(ADDRINT ip, ADDRINT memaddr,
		ADDRINT writesize)
{
	treeNode *node = FindInRange(bst_root, memaddr);
	if(node != NULL)
	{
//		fprintf(trace, "wirte size %lx\n", writesize);
		struct log* log = (struct log*)malloc(sizeof(struct log));
		log->time = get_timer();
		log->address = memaddr;
		log->size = writesize;
		log->isread = FALSE;
		InsertLog(node, log);
	}
}

// Is called for every instruction and instruments syscalls
VOID Instruction(INS ins, VOID *v)
{
	if(INS_Valid(ins) && INS_IsMemoryWrite(ins) && !(INS_IsStackWrite(ins) || INS_IsBranchOrCall(ins)))
	{
		int threadid = PIN_GetTid();
		if(per_thread_buf[0][threadid] == NULL)
		{
			per_thread_buf[0][threadid] = (char*)malloc(sizeof(char)*MAX_BUFSIZE);
		}
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(MemoryWrite),
				IARG_INST_PTR,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYWRITE_SIZE,
				IARG_END);
	}
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
}

VOID Fini(INT32 code, VOID *v)
{
	fprintf(trace, "%x %x\n", PIN_GetTid(), PROCESSEND);
	fclose(trace);
	while(bst_root != NULL)
		bst_root = Delete(bst_root, bst_root->address);
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

BOOL FollowChild(CHILD_PROCESS chidProcess, VOID *userData)
{
	return TRUE;
}


VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	int threadid = PIN_GetTid();
	char buf[100];
	sprintf(buf, "%x %x thread end\n", threadid, THREADEND);
	fprintf(trace, "%s", buf);
	fflush(trace);
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

	fprintf(trace, "%x\n", pid);

	root_thread = (struct thread*)malloc(sizeof(struct thread));
	root_thread->tid = PIN_GetTid();
	root_thread->parent = NULL;
	root_thread->children = NULL;
	root_thread->fd_own = NULL;
	root_thread->fd_inherit = NULL;

//	PIN_AddFollowChildProcessFunction(FollowChild, 0);
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);


	// Write to a file since cout and cerr maybe closed by the application
	TraceFile.open(KnobOutputFile.Value().c_str());
	TraceFile << hex;
	TraceFile.setf(ios::showbase);

	IMG_AddInstrumentFunction(Image, 0);

	PIN_AddFiniFunction(Fini, 0);

	set_timer();

	// Never returns
	PIN_StartProgram();

	return 0;
}
