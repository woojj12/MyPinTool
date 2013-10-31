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

/* ===================================================================== */
/*
  @ORIGINAL_AUTHOR: Robert Cohn
*/

/* ===================================================================== */
/*! @file
  Generates a trace of malloc/free calls
 */

#include "pin.H"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <syscall.h>
#include <sched.h>

#include <iostream>
#include <fstream>

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

#define THREADSTART 1000	//3e8
#define THREADEND	1001
#define PROCESSEND	1002

#define _MALLOC	2000	//7d0
#define _FREE	2001
#define MEMORY	2002
#define STACK	2003
#define RETURN	2004	//7d4

#define MALLOC_READ	3000	//bb8
#define STACK_READ	3001
#define DATA_READ	3002

#define SYS_NONE	9999

using namespace std;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

PIN_MUTEX thread_lock, malloc_lock, data_lock;

FILE *trace;
long unsigned int pagesize;

typedef VOID * (*FUNCPTR_MALLOC)(size_t);
typedef VOID * (*FUNCPTR_REALLOC)(void*, size_t);

//VOID ReplaceJitted( RTN rtn, PROTO proto_malloc );
VOID * Malloc( CONTEXT * context, AFUNPTR orgFuncptr, size_t arg0 );
VOID * Realloc( CONTEXT * context, AFUNPTR orgFuncptr, void * ptr, size_t arg0 );
VOID   Free( CONTEXT * context, AFUNPTR orgFuncptr, void * arg0 );

typedef struct treeNode
{
	PIN_THREAD_UID threadid;

	ADDRINT address;
	ADDRINT size;
	BOOL usedforread;
	ADDRINT offset;

	int fd;

	struct treeNode *left;
	struct treeNode *right;

}treeNode;

typedef struct FD
{
	int fd;
	char* path;

	treeNode *buffer;

	struct FD *left;
	struct FD *right;
} FD;

treeNode * InsertDAddress(treeNode *node, ADDRINT address, int fd, ADDRINT size, ADDRINT offset);
treeNode * InsertMAddress(treeNode *node, ADDRINT address, ADDRINT size, ADDRINT offset);
treeNode * InsertSAddress(treeNode *node, ADDRINT address, int fd, ADDRINT size, ADDRINT offset);

FD* FindFD(FD *_node, int fd)
{
	FD *node = _node;
	while(node != NULL)
	{
		if(node->fd == fd)
			return node;
		else if(node->fd > fd)
			node = node->left;
		else
			node = node->right;
	}
	return NULL;
}

FD* FindMinFD(FD *node)
{
	if(node==NULL)
	{
		/* There is no element in the tree */
		return NULL;
	}
	if(node->left) /* Go to the left sub tree to find the min element */
		return FindMinFD(node->left);
	else
		return node;
}

FD* FindMaxFD(FD *node)
{
	if(node==NULL)
	{
		/* There is no element in the tree */
		return NULL;
	}
	if(node->right) /* Go to the left sub tree to find the min element */
		return FindMaxFD(node->right);
	else
		return node;
}

FD* InsertFD(FD *node, int fd, char* path)
{
	if(node == NULL)
	{
		node = (FD*)malloc(sizeof(FD));
		node->fd = fd;
		node->path = path;
		node->left = NULL;
		node->right = NULL;
		node->buffer = NULL;
	}
	else
	{
		if(node->fd < fd)
			node->right = InsertFD(node->right, fd, path);
		else if(node->fd > fd)
			node->left = InsertFD(node->left, fd, path);
		else
		{
//			assert(0);
			node->fd = fd;
			assert(node->path);
			free(node->path);
			node->path = path;
		}
	}
	return node;
}

FD* DeleteFD(FD* node, int fd)
{
	FD *temp;
	assert(node);
	if(fd < node->fd)
	{
		node->left = DeleteFD(node->left, fd);
	}
	else if(fd > node->fd)
	{
		node->right = DeleteFD(node->right, fd);
	}
	else
	{
		/* Now We can delete this node and replace with either minimum element
                   in the right sub tree or maximum element in the left subtree */
		if(node->right && node->left)
		{
			/* Here we will replace with minimum element in the right sub tree */
			temp = FindMinFD(node->right);
			node -> fd = temp->fd;
			free(node->path);
			node->path = temp->path;
			temp->path = NULL;

			/* As we replaced it with some other node, we have to delete that node */
			node -> right = DeleteFD(node->right, temp->fd);
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

typedef struct FD_TABLE
{
	int sharecount;
	int count;
	PIN_MUTEX lock;
	FD *root;
}FD_TABLE;

FD* CopyFD_TABLE(FD* parent)
{
	if(parent == NULL)
		return NULL;

	FD* newnode = (FD*)malloc(sizeof(FD));
	newnode->fd = parent->fd;
	newnode->path = strdup(parent->path);
	newnode->buffer = NULL;

	newnode->left = CopyFD_TABLE(parent->left);
	newnode->right = CopyFD_TABLE(parent->right);

	return newnode;
}

void FreeFD_TABLE(FD* node)
{
	if(node == NULL)
		return;

	if(node->path != NULL)
	{
		free(node->path);
		node->path = NULL;
	}
	FreeFD_TABLE(node->left);
	FreeFD_TABLE(node->right);
}

treeNode *malloc_root, *data_root;//, *stack_root;

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

treeNode * InsertDAddress(treeNode *node, ADDRINT address, int fd, ADDRINT size, ADDRINT offset)
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
		return temp;
	}

	if(address >(node->address))
	{
		node->right = InsertDAddress(node->right,address,fd,size, offset);
	}
	else if(address < (node->address))
	{
		node->left = InsertDAddress(node->left,address,fd,size, offset);
	}
	else
	{
		node->size = size;
		node->offset = offset;
		node->usedforread = TRUE;
	}
	/* Else there is nothing to do as the data is already in the tree. */
	return node;
}

treeNode * InsertSAddress(treeNode *node, ADDRINT address, int fd, ADDRINT size, ADDRINT offset)
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
		return temp;
	}

	if(address >(node->address))
	{
		node->right = InsertSAddress(node->right,address,fd,size, offset);
	}
	else if(address < (node->address))
	{
		node->left = InsertSAddress(node->left,address,fd,size, offset);
	}
	else
	{
		node->fd = fd;
		node->size = size;
		node->offset = offset;
		node->usedforread = TRUE;
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
		temp -> threadid = PIN_ThreadUid();
		temp -> address = address;
		temp->offset = offset;
		temp -> size = size;
		temp -> usedforread = FALSE;
		temp -> left = temp -> right = NULL;
//	    fprintf(trace, "%lx malloc %lx %lx\n", PIN_ThreadUid(), size, address);
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
		if(node->size == size && node->address == address && node->threadid == PIN_ThreadUid())
		{
			return node;
		}
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
//    	fprintf(trace, "%lx free %lx\n", PIN_ThreadUid(), address);
		/* Now We can delete this node and replace with either minimum element
                   in the right sub tree or maximum element in the left subtree */
		if(node->right && node->left)
		{
			/* Here we will replace with minimum element in the right sub tree */
			temp = FindMinAddress(node->right);
			node -> address = temp->address;
			node->size = temp->size;
			node->usedforread = temp->usedforread;

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
	if(address > node->address + node->size)
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
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "jitmalloctrace.outfile", "specify trace file name");

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

struct thread
{
	PIN_THREAD_UID tid;
	OS_THREAD_ID OStid;
	char *buffer;
	int flag;
	treeNode *stack;
	FD_TABLE *fdtable;

	char* newfdpath;

	struct thread *left, *right;
};
struct thread *root_thread;

struct thread* FindThreadByOSTid(struct thread *node, OS_THREAD_ID threadid)
{
	if(node == NULL)
		return NULL;

	if(node->OStid == threadid)
		return node;

	struct thread *ret;
	ret = FindThreadByOSTid(node->left, threadid);
	if(ret != NULL)
		return ret;

	ret = FindThreadByOSTid(node->right, threadid);
	if(ret != NULL)
		return ret;

	return NULL;
}

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

struct thread* FindMinThread(struct thread *node)
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

struct thread* FindMaxThread(struct thread *node)
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

struct thread* InsertThread(PIN_THREAD_UID threadid, struct thread *node)
{
	if(node == NULL)
	{
		node = (struct thread*)malloc(sizeof(struct thread));
		assert(node);
		node->tid = threadid;
		node->OStid = PIN_GetTid();
		node->flag = 0;
		node->left = NULL;
		node->right = NULL;
		node->buffer = (char*)malloc(sizeof(char)*MAX_BUFSIZE);
		assert(node->buffer);
		node->stack = NULL;
		node->fdtable = NULL;
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
			free(node->buffer);
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
			free(temp->buffer);
			free(temp); /* temp is longer required */
		}
	}
	return node;
}

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT sp)
{
	//	unsigned int i;
	//	struct iovec* vec;
	//	char buf[MAX_BUFSIZE];

	treeNode *node;

	ADDRINT addr;

	off_t offset;
	FD *fd;

	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_MutexLock(&thread_lock);
	struct thread* thread = FindThread(threadid);
	assert(thread);
	PIN_MutexUnlock(&thread_lock);
	thread->flag = SYS_NONE;

	switch(num)
	{
	case SYS_READ:
		//arg0 : fd
		//arg1 : buf addr
		//arg2 : buf size

		//stdin
		if(arg0 == 0)
			break;

		PIN_MutexLock(&thread->fdtable->lock);
		fd = FindFD(thread->fdtable->root, arg0);
		PIN_MutexUnlock(&thread->fdtable->lock);

		assert(fd);

		offset = lseek((int)arg0, 0, SEEK_CUR);
//
		fd->buffer = InsertDAddress(fd->buffer, arg1, fd->fd, 0, 0);

		PIN_MutexLock(&malloc_lock);
		node = FindAddressInRange(malloc_root, arg1);
		PIN_MutexUnlock(&malloc_lock);
		if(node != NULL)
		{
			node->usedforread = TRUE;
			node->offset = offset;
			node->fd = (int)arg0;
			//bb8
			sprintf(thread->buffer, "%lx %x %lx %lx %lx %lx ", threadid, MALLOC_READ, arg0, arg1, arg2, offset);
		}
		else if(arg1 >= sp - pagesize)
		{
			//bb9
			thread->stack = InsertSAddress(thread->stack, arg1, (int)arg0, arg2, offset);
			sprintf(thread->buffer, "%lx %x %lx %lx %lx %lx ", threadid, STACK_READ, arg0, arg1, arg2, offset);
		}
		else
		{
			//bba
			PIN_MutexLock(&data_lock);
			data_root = InsertDAddress(data_root, arg1, (int)arg0, arg2, offset);
			PIN_MutexUnlock(&data_lock);
			sprintf(thread->buffer, "%lx %x %lx %lx %lx %lx ", threadid, DATA_READ, arg0, arg1, arg2, offset);
		}
		thread->flag = SYS_READ;
		return;

	case SYS_WRITE:
		if(arg0 == 1 || arg0 == 2)
			break;

		offset = lseek((int)arg0, 0, SEEK_CUR);
		sprintf(thread->buffer, "%lx %lx %lx %lx %lx %lx ", threadid, num, arg0, arg1, arg2, offset);
		thread->flag = SYS_WRITE;
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
		thread->flag = SYS_LSEEK;
		break;

	case SYS_FCNTL:
		if(arg1 == F_DUPFD || arg1 == F_DUPFD_CLOEXEC)
		{
			sprintf(thread->buffer, "%lx %lx %lx ", threadid, num, arg0);
			PIN_MutexLock(&thread->fdtable->lock);
			fd = FindFD(thread->fdtable->root, arg0);
			PIN_MutexUnlock(&thread->fdtable->lock);

			assert(fd);

			thread->newfdpath = strdup(fd->path);
			thread->flag = SYS_DUP;
			break;
		}
		else
		{
			thread->flag = SYS_NONE;
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
		thread->newfdpath = strdup((const char*)arg1);
		thread->flag = SYS_OPEN;
		break;

	case SYS_CREAT:
	case SYS_OPEN:
		sprintf(thread->buffer, "%lx %lx %s ", threadid, num, (char*)arg0);
		thread->newfdpath = strdup((const char*)arg0);
		thread->flag = SYS_OPEN;
		break;

	case SYS_CLOSE:
		if(arg0 == 0 || arg0 == 1 || arg0 == 2)
			break;
		PIN_MutexLock(&thread->fdtable->lock);
		fd = FindFD(thread->fdtable->root, arg0);
		PIN_MutexUnlock(&thread->fdtable->lock);

		assert(fd);

		while(fd->buffer)
		{
			addr = fd->buffer->address;

			//malloc
			PIN_MutexLock(&malloc_lock);
			node = FindAddressInRange(malloc_root, addr);
			PIN_MutexUnlock(&malloc_lock);
			if(node != NULL)
				node->usedforread = FALSE;
			//stack
			else
			{
				node = FindAddressInRange(thread->stack, addr);
				if(node)
				{
					thread->stack = DeleteAddress(thread->stack, node->address);
				}
				else
				{
					//data
					PIN_MutexLock(&data_lock);
					node = FindAddressInRange(data_root, addr);
					if(node)
					{
						data_root = DeleteAddress(data_root, node->address);
					}
					PIN_MutexUnlock(&data_lock);
				}
			}
			fd->buffer = DeleteAddress(fd->buffer, addr);
		}

		sprintf(thread->buffer, "%lx %lx %lx ", threadid, num, arg0);
		PIN_MutexLock(&thread->fdtable->lock);
		thread->fdtable->root = DeleteFD(thread->fdtable->root, arg0);
		PIN_MutexUnlock(&thread->fdtable->lock);

		thread->flag = SYS_CLOSE;
		break;

//	case SYS_EXIT:
//	case SYS_EXIT_GROUP:
//	case SYS_FORK:
//	case SYS_VFORK:
//		sprintf(thread->buffer, "%lx %lx %lx ", threadid, num, arg0);
//		fprintf(trace, "%s\n", thread->buffer);
//		fflush(trace);
//		thread->buffer[0] = '\0';
//		thread->flag = SYS_NONE;
//		return;

	case SYS_CLONE:
		sprintf(thread->buffer, "%lx %lx %lx %lx %lx ", threadid, num, arg0, arg1, arg2);
		if(arg0 & CLONE_FILES)
		{
			thread->buffer = strcat(thread->buffer, "files ");
		}
		if(arg0 & CLONE_NEWPID)
		{
			thread->buffer = strcat(thread->buffer, "newpid ");
		}
		if(arg0 & CLONE_VM)
		{
			thread->buffer = strcat(thread->buffer, "vm ");
		}
		if(arg0 & CLONE_THREAD)
		{
			thread->buffer = strcat(thread->buffer, "thread ");
		}
		if(arg0 & CLONE_IO)
		{
			thread->buffer = strcat(thread->buffer, "io ");
		}
//		thread->flag = SYS_CLONE;
		thread->flag = SYS_NONE;
//		thread->flag = 1;
		return;

	case SYS_EXECVE:
		sprintf(thread->buffer, "%lx %lx %s ", threadid, num, (char*)arg0);
		fprintf(trace, "%s\n", thread->buffer);
		thread->buffer[0] = '\0';
		fflush(trace);
		thread->flag = 0;
		PIN_MutexLock(&thread_lock);
		root_thread = DeleteThread(threadid, root_thread);
		PIN_MutexUnlock(&thread_lock);
		thread->flag = SYS_NONE;
		break;

	default :
		thread->flag = SYS_NONE;
		return;
	}
//	thread->flag = 1;
}

// Print the return value of the system call
VOID SysAfter(ADDRINT ret, ADDRINT num)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_MutexLock(&thread_lock);
	struct thread *thread = FindThread(threadid);
	PIN_MutexUnlock(&thread_lock);
	if(ret+1 == 0)
	{
		thread->flag = SYS_NONE;
		thread->buffer[0] = '\0';
		return;
	}
	if(thread->flag != SYS_NONE)
	{
//		if(!(thread->flag == 3 && ((ret+1 == 0) || (ret == 0))))
		{
			char buf[MAX_BUFSIZE];

			sprintf(buf,"%x\n", (unsigned int)ret);
			strcat(thread->buffer, buf);
			fprintf(trace, "%s", thread->buffer);
			fflush(trace);
			thread->buffer[0] = '\0';
		}
		if(thread->flag == SYS_OPEN || thread->flag == SYS_DUP)
		{
			if(ret+1 != 0)
			{
				PIN_MutexLock(&thread->fdtable->lock);
				thread->fdtable->root = InsertFD(thread->fdtable->root, ret, thread->newfdpath);
				PIN_MutexUnlock(&thread->fdtable->lock);
			}
		}
		thread->flag = SYS_NONE;
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
			PIN_GetSyscallArgument(ctxt, std, 5),
			PIN_GetContextReg(ctxt,REG_STACK_PTR));
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	SysAfter(PIN_GetSyscallReturn(ctxt, std), PIN_GetSyscallNumber(ctxt, std));
}

VOID MemoryWrite(ADDRINT memaddr, ADDRINT writesize)
{
	treeNode *node;
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	FD *fd;
	PIN_MutexLock(&thread_lock);
	struct thread* thread = FindThread(threadid);
	PIN_MutexUnlock(&thread_lock);

	ADDRINT startoffset, endoffset;

	PIN_MutexLock(&data_lock);
	node = FindAddressInRange(data_root, memaddr);
	PIN_MutexUnlock(&data_lock);
	if(node && node->usedforread == TRUE)
	{
		fprintf(trace, "%lx %x %lx %lx\n", threadid, MEMORY, memaddr, writesize);
		PIN_MutexLock(&thread->fdtable->lock);
		fd = FindFD(thread->fdtable->root, node->fd);
		PIN_MutexUnlock(&thread->fdtable->lock);
		assert(fd);

		startoffset = memaddr - node->address + node->offset;
		endoffset = memaddr - node->address + node->offset + writesize;

		fprintf(trace, "%s %lx %lx\n", fd->path, startoffset, endoffset);
		return;
	}
	PIN_MutexLock(&malloc_lock);
	node = FindAddressInRange(malloc_root, memaddr);
	PIN_MutexUnlock(&malloc_lock);
	if(node && node->usedforread == TRUE)
	{
		fprintf(trace, "%lx %x %lx %lx\n", threadid, MEMORY, memaddr, writesize);
		PIN_MutexLock(&thread->fdtable->lock);
		fd = FindFD(thread->fdtable->root, node->fd);
		PIN_MutexUnlock(&thread->fdtable->lock);

		assert(fd);

		startoffset = memaddr - node->address + node->offset;
		endoffset = memaddr - node->address + node->offset + writesize;

		fprintf(trace, "%s %lx %lx\n", fd->path, startoffset, endoffset);
	}
}

VOID StackWrite(ADDRINT memaddr, ADDRINT writesize)
{
	treeNode *node;
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	FD *fd;
	ADDRINT startoffset, endoffset;

	PIN_MutexLock(&thread_lock);
	struct thread* thread = FindThread(threadid);
	PIN_MutexUnlock(&thread_lock);

	node = FindAddressInRange(thread->stack, memaddr);
	if(node && node->usedforread == TRUE)
	{
		fprintf(trace, "%lx %x %lx %lx\n", threadid, STACK, memaddr, writesize);
		PIN_MutexLock(&thread->fdtable->lock);
		fd = FindFD(thread->fdtable->root, node->fd);
		PIN_MutexUnlock(&thread->fdtable->lock);

		assert(fd);

		startoffset = memaddr - node->address + node->offset;
		endoffset = memaddr - node->address + node->offset + writesize;

		fprintf(trace, "%s %lx %lx\n", fd->path, startoffset, endoffset);
	}
}

VOID Return(ADDRINT sp)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_MutexLock(&thread_lock);
	struct thread* thread = FindThread(threadid);
	PIN_MutexUnlock(&thread_lock);
	treeNode *node = FindMinAddress(thread->stack);
	if(node == NULL)
		return;
	while(node->address <= sp)
	{
//		fprintf(trace, "%lx %x %lx\n", threadid, RETURN, node->address);
		thread->stack = DeleteAddress(thread->stack, node->address);
		node = FindMinAddress(thread->stack);
		if(node == NULL)
			return;
	}
}

// Is called for every instruction and instruments syscalls & store
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


/* ===================================================================== */
// Called every time a new image is loaded.
// Look for routines that we want to replace.
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

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{

	PIN_MutexLock(&malloc_lock);
	while(malloc_root != NULL)
		malloc_root = DeleteAddress(malloc_root, malloc_root->address);
	PIN_MutexUnlock(&malloc_lock);

	PIN_MutexLock(&data_lock);
	while(data_root != NULL)
		data_root = DeleteAddress(data_root, data_root->address);
	PIN_MutexUnlock(&data_lock);

	PIN_MutexLock(&thread_lock);
	while(root_thread != NULL)
		root_thread = DeleteThread(root_thread->tid, root_thread);
	PIN_MutexUnlock(&thread_lock);

	PIN_MutexFini(&thread_lock);
	PIN_MutexFini(&data_lock);
	PIN_MutexFini(&malloc_lock);

//	fprintf(trace, "%lx %x\n", PIN_ThreadUid(), PROCESSEND);
	fclose(trace);
}

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_MutexLock(&thread_lock);
	struct thread *temp = FindThread(threadid);
	if(temp == NULL)
		root_thread = InsertThread(threadid, root_thread);
	temp = FindThread(threadid);
	PIN_MutexUnlock(&thread_lock);
//	fprintf(trace, "%lx %x %x %x\n",  threadid, THREADSTART, PIN_GetTid(), PIN_GetParentTid());
	temp->fdtable = (FD_TABLE*)malloc(sizeof(FD_TABLE));

	if(PIN_GetParentTid() == 0)
	{
		//no parent
		PIN_MutexInit(&temp->fdtable->lock);
		temp->fdtable->count = 0;
		temp->fdtable->root = NULL;
		temp->fdtable->sharecount = 1;
	}
	else
	{
		PIN_MutexLock(&thread_lock);
		struct thread *parent = FindThreadByOSTid(root_thread, PIN_GetParentTid());
		PIN_MutexUnlock(&thread_lock);

		PIN_MutexInit(&temp->fdtable->lock);
		temp->fdtable->count = 0;
		temp->fdtable->root = NULL;
		temp->fdtable->sharecount = 1;
		PIN_MutexLock(&parent->fdtable->lock);
		temp->fdtable->root = CopyFD_TABLE(parent->fdtable->root);
		PIN_MutexUnlock(&parent->fdtable->lock);
	}
	fflush(trace);
}

VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
//	fprintf(trace, "%lx %x\n", threadid, THREADEND);
	fflush(trace);
	PIN_MutexLock(&thread_lock);
	struct thread* node = FindThread(threadid);
	PIN_MutexUnlock(&thread_lock);

	PIN_MutexLock(&node->fdtable->lock);
	node->fdtable->sharecount--;
	if(node->fdtable->sharecount == 0)
	{
		FreeFD_TABLE(node->fdtable->root);
	}
	PIN_MutexUnlock(&node->fdtable->lock);

	PIN_MutexFini(&node->fdtable->lock);
	free(node->fdtable);

	PIN_MutexLock(&thread_lock);
	root_thread = DeleteThread(threadid, root_thread);
	PIN_MutexUnlock(&thread_lock);
}

int main(int argc, CHAR *argv[])
{
    PIN_InitSymbols();

	pagesize = getpagesize();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    char *buf = (char*)malloc(sizeof(char)*100);
    assert(buf);

    sprintf(buf, "trace_%x", getpid());

    trace = fopen(buf, "a");

    free(buf);
    buf = NULL;

	PIN_MutexInit(&malloc_lock);
	PIN_MutexInit(&thread_lock);
	PIN_MutexInit(&data_lock);

    IMG_AddInstrumentFunction(ImageLoad, 0);

	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}


/* ===================================================================== */

VOID * Malloc( CONTEXT * context, AFUNPTR orgFuncptr, size_t size)
{
    VOID * ret;

    PIN_CallApplicationFunction( context, PIN_ThreadId(),
                                 CALLINGSTD_DEFAULT, orgFuncptr,
                                 PIN_PARG(void *), &ret,
                                 PIN_PARG(size_t), size,
                                 PIN_PARG_END() );

	PIN_MutexLock(&malloc_lock);
	malloc_root = InsertMAddress(malloc_root, (ADDRINT)ret, size, 0);
	PIN_MutexUnlock(&malloc_lock);
    return ret;
}

/* ===================================================================== */

VOID * Realloc( CONTEXT * context, AFUNPTR orgFuncptr, void * ptr, size_t size)
{
    VOID * ret;

    PIN_CallApplicationFunction( context, PIN_ThreadId(),
                                 CALLINGSTD_DEFAULT, orgFuncptr,
                                 PIN_PARG(void *), &ret,
                                 PIN_PARG(void *), ptr,
                                 PIN_PARG(size_t), size,
                                 PIN_PARG_END() );

	PIN_MutexLock(&malloc_lock);
    if(ptr != NULL)
    {
    	if(!FindAddress(malloc_root, (ADDRINT)ret))
    	{
			malloc_root = DeleteMAddress(malloc_root, (ADDRINT)ptr);
			malloc_root = InsertMAddress(malloc_root, (ADDRINT)ret, size, 0);
    	}
    }
	PIN_MutexUnlock(&malloc_lock);
    return ret;
}

/* ===================================================================== */

VOID Free( CONTEXT * context, AFUNPTR orgFuncptr, void * ptr)
{
    if(ptr != NULL)
    {
    	if(!FindAddress(malloc_root, (ADDRINT)ptr))
    	{
			PIN_MutexLock(&malloc_lock);
			malloc_root = DeleteMAddress(malloc_root, (ADDRINT)ptr);
			PIN_MutexUnlock(&malloc_lock);
    	}
    }

    PIN_CallApplicationFunction( context, PIN_ThreadId(),
                                 CALLINGSTD_DEFAULT, orgFuncptr,
                                 PIN_PARG(void),
                                 PIN_PARG(void *), ptr,
                                 PIN_PARG_END() );
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
