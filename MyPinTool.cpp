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
#include <stdlib.h>
#include <assert.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <iostream>

//#include <sys/types.h>
//#include <sys/time.h>
//#include <unistd.h>
//#include <sys/types.h>
//#include <fcntl.h>
//#include <sys/mman.h>
//#include <errno.h>
//#include <sched.h>

//#include <fstream>

//linux kernel 3.10
//x86_64 sys call number

//file open/close
#define SYS_OPEN	__NR_open//2
#define SYS_CLOSE	__NR_close//3
#define SYS_PIPE	__NR_pipe	//22	//16
#define SYS_DUP __NR_dup	//32	//20
#define SYS_DUP2	__NR_dup2//33	//21
#define SYS_SOCKET	__NR_socket//41	//29
#define SYS_SOCKETPAIR	__NR_socketpair//53
#define SYS_CREAT	__NR_creat//85	//55
#define SYS_OPENAT	__NR_openat//257	//101
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

#define MAX_BUFSIZE	1024

#define THREADSTART 1000	//3e8
#define THREADEND	1001
#define PROCESSEND	1002

#define _MALLOC	2000	//7d0
#define _FREE	2001
//#define MEMORY	2002
#define MALLOC	2002
#define DATA	2003
#define STACK	2004
#define RETURN	2005	//7d4

#define MALLOC_READ	3000	//bb8
#define STACK_READ	3001
#define DATA_READ	3002

#define SYS_NONE	9999
#define SYS_FDETC	9998

#define COW	9997

using namespace std;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

PIN_RWMUTEX thread_lock, malloc_lock, data_lock;
PIN_MUTEX readid_lock;

FILE *trace;
long unsigned int pagesize;
int pid;
long unsigned int readid;

typedef VOID * (*FUNCPTR_MALLOC)(size_t);
typedef VOID * (*FUNCPTR_REALLOC)(void*, size_t);

//VOID ReplaceJitted( RTN rtn, PROTO proto_malloc );
VOID * Malloc( CONTEXT * context, AFUNPTR orgFuncptr, size_t arg0 );
VOID * Realloc( CONTEXT * context, AFUNPTR orgFuncptr, void * ptr, size_t arg0 );
VOID   Free( CONTEXT * context, AFUNPTR orgFuncptr, void * arg0 );

long unsigned int GetReadId()
{
	long unsigned int ret;

	PIN_MutexLock(&readid_lock);
	ret = readid;
	readid++;
	PIN_MutexUnlock(&readid_lock);

	return ret;
}

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

treeNode * InsertDAddress(treeNode *node, ADDRINT address, int fd, ADDRINT size, ADDRINT offset, char* buf, long unsigned int readid);
treeNode * InsertMAddress(treeNode *node, ADDRINT address, ADDRINT size, ADDRINT offset);
treeNode * InsertSAddress(treeNode *node, ADDRINT address, int fd, ADDRINT size, ADDRINT offset, char* buf, long unsigned int readid);

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

struct thread
{
	PIN_THREAD_UID tid;
	treeNode *stack;

	char buffer[MAX_BUFSIZE];

	struct thread *left, *right;
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

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, ADDRINT sp)
{
	//	unsigned int i;
	//	struct iovec* vec;

	treeNode *node;

//	ADDRINT addr;

	struct stat stat;
	off_t offset;
	char buf[2][MAX_BUFSIZE];
	int tmp;
	int i;
	long unsigned int readid;

	struct iovec *vec;

	long unsigned int size;

	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_RWMutexReadLock(&thread_lock);
	struct thread* thread = FindThread(threadid);
	assert(thread);
	PIN_RWMutexUnlock(&thread_lock);

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


		sprintf(buf[0], "/proc/self/fd/%d", (int)arg0);
		tmp = readlink(buf[0], buf[1], MAX_BUFSIZE);

		if(buf[1][0] != '/')
			break;

		if(strncmp(buf[1], "/proc", 5) == 0)
			break;

		buf[1][tmp] = '\0';

		if(num == SYS_READ)
		{
		offset = lseek((int)arg0, 0, SEEK_CUR);
		if(offset+1 == 0)
			offset = 0;
		}
		else
		{
			offset = arg3;
		}

		size = fstat((int)arg0, &stat);
		assert(size == 0);

		size = stat.st_size;
		if(offset+arg2 > size)
			size = size - offset;
		else
			size = arg2;

		if(size <= 0)
			break;

		readid = GetReadId();

		sprintf(thread->buffer, "%s:%lx:%lx:%lx:", buf[1], offset, size, stat.st_size);

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
			//bb8
			strcat(thread->buffer, "M");
		}
		else if(arg1 >= sp - pagesize)
		{
			//bb9
			thread->stack = InsertSAddress(thread->stack, arg1, (int)arg0, size, offset, buf[1], readid);
			strcat(thread->buffer, "S");
		}
		else
		{
			//bba
			PIN_RWMutexWriteLock(&data_lock);
			data_root = InsertDAddress(data_root, arg1, (int)arg0, size, offset, buf[1], readid);
			PIN_RWMutexUnlock(&data_lock);
			strcat(thread->buffer, "D");
		}
		fprintf(trace, "%s\n", thread->buffer);
		break;

	case SYS_PREADV:
	case SYS_READV:
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
				//bb8
//				sprintf(thread->buffer, "%x:%lx:%lx:%lx:%lx:", MALLOC_READ, arg0, (ADDRINT)vec[i].iov_base, vec[i].iov_len, offset);
			}
			else if(arg1 >= sp - pagesize)
			{
				//bb9
				strcat(thread->buffer, "S");
				thread->stack = InsertSAddress(thread->stack, arg1, (int)arg0, size, offset, buf[1], readid);
//				sprintf(thread->buffer, "%x:%lx:%lx:%lx:%lx:", STACK_READ, arg0, (ADDRINT)vec[i].iov_base, vec[i].iov_len, offset);
			}
			else
			{
				//bba
				strcat(thread->buffer, "D");
				PIN_RWMutexWriteLock(&data_lock);
				data_root = InsertDAddress(data_root, arg1, (int)arg0, size, offset, buf[1], readid);
				PIN_RWMutexUnlock(&data_lock);
//				sprintf(thread->buffer, "%x:%lx:%lx:%lx:%lx:", DATA_READ, arg0, (ADDRINT)vec[i].iov_base, vec[i].iov_len, offset);
			}
			fprintf(trace, "%s\n", thread->buffer);
		}
		break;

//	case SYS_WRITE:
//	case SYS_PWRITE64:
//		if(arg0 == 1 || arg0 == 2)
//			break;
//
//		if(num == SYS_WRITE)
//		{
//			offset = lseek((int)arg0, 0, SEEK_CUR);
//			if(offset + 1 == 0)
//				offset = 0;
//		}
//		else
//			offset = arg3;
//
//		sprintf(thread->buffer, "%lx:%lx:%lx:%lx:%lx:", num, arg0, arg1, arg2, offset);
//		thread->flag = SYS_WRITE;
//		return;
//
//	case SYS_PWRITEV:
//	case SYS_WRITEV:
//		//stdin
//		if(arg0 == 0)
//			break;
//
//		sprintf(buf[0], "/proc/self/fd/%d", (int)arg0);
//		tmp = readlink(buf[0], buf[1], MAX_BUFSIZE);
//		buf[1][tmp] = '\0';
//
//		if(num == SYS_PWRITEV)
//		{
//			offset = lseek((int)arg0, 0, SEEK_CUR);
//			if(offset + 1 == 0)
//				offset = 0;
//		}
//		else
//			offset = arg3;
//
//		vec = (struct iovec *)arg1;
//		for(i=0; i < (int)arg2; i++)
//		{
//			sprintf(thread->buffer, "%lx:%lx:%lx:%lx:%lx:", num, arg0, (ADDRINT)vec[i].iov_base, vec[i].iov_len, offset);
//		}
//		thread->flag = SYS_PWRITEV;
//		return;

//	case SYS_LSEEK:
//		sprintf(thread->buffer, "%lx:%lx:%lx:%lx:", num, arg0, arg1, arg2);
//		thread->flag = SYS_LSEEK;
//		break;

//	case SYS_FCNTL:
//		if(arg1 == F_DUPFD || arg1 == F_DUPFD_CLOEXEC)
//		{
//			sprintf(thread->buffer, "%x:", SYS_OPEN);
//			thread->flag = SYS_OPEN;
//		}
//		break;
//		else
//		{
//			thread->flag = SYS_NONE;
//			return;
//		}

//	case SYS_OPENAT:
//	case SYS_CREAT:
//	case SYS_OPEN:
//
//	case SYS_DUP:
//	case SYS_DUP2:
//	case SYS_DUP3:
//
//	case SYS_ACCEPT:
//	case SYS_ACCEPT4:
//	case SYS_EPOLL_CREATE:
//	case SYS_SOCKET:
//	case SYS_PIPE:
//	case SYS_PIPE2:
//	case SYS_SIGNALFD:
//	case SYS_TIMERFD_CREATE:
//	case SYS_EVENTFD:
//	case SYS_SIGNALFD4:
//	case SYS_EVENTFD2:
//		sprintf(thread->buffer, "%x:", SYS_OPEN);
//		thread->flag = SYS_OPEN;
//		break;
//
//	case SYS_CLOSE:
//		if(arg0 == 0 || arg0 == 1 || arg0 == 2)
//			break;
//
//		sprintf(thread->buffer, "%lx:%lx:", num, arg0);
//
//		thread->flag = SYS_CLOSE;
//		break;

//	case SYS_CLONE:
//		sprintf(thread->buffer, "%lx|%lx|%lx|%lx|", num, arg0, arg1, arg2);
//		if(arg0 & CLONE_FILES)
//		{
//			thread->buffer = strcat(thread->buffer, "files|");
//		}
//		if(arg0 & CLONE_NEWPID)
//		{
//			thread->buffer = strcat(thread->buffer, "newpid|");
//		}
//		if(arg0 & CLONE_VM)
//		{
//			thread->buffer = strcat(thread->buffer, "vm|");
//		}
//		if(arg0 & CLONE_THREAD)
//		{
//			thread->buffer = strcat(thread->buffer, "thread|");
//		}
//		if(arg0 & CLONE_IO)
//		{
//			thread->buffer = strcat(thread->buffer, "io|");
//		}
//		thread->flag = SYS_NONE;
//		return;

//	case SYS_EXECVE:
//		sprintf(thread->buffer, "%lx|%lx|%s|", threadid, num, (char*)arg0);
//		fprintf(trace, "%s\n", thread->buffer);
//		thread->buffer[0] = '\0';
//		fflush(trace);
//		thread->flag = 0;
//		PIN_MutexLock(&thread_lock);
//		root_thread = DeleteThread(threadid, root_thread);
//		PIN_MutexUnlock(&thread_lock);
//		thread->flag = SYS_NONE;
//		break;

//	default :
////		sprintf(thread->buffer, "%ld ", num);
////		fprintf(trace, "%ld\n", num);
//		thread->flag = SYS_NONE;
//		return;
	}
//	thread->flag = 1;
}

// Print the return value of the system call
VOID SysAfter(ADDRINT ret)
{
//	PIN_THREAD_UID threadid = PIN_ThreadUid();
//	PIN_MutexLock(&thread_lock);
//	struct thread *thread = FindThread(threadid);
//	PIN_MutexUnlock(&thread_lock);
//	char buf[2][MAX_BUFSIZE];
//	int tmp;
//
////	fprintf(stderr, "%ld\n", ret);
//
//	struct stat stat;
//	int statret;
//	off_t filesize;

//	if(ret+1 == 0)
//	{
//		thread->flag = SYS_NONE;
//		thread->buffer[0] = '\0';
//		return;
//	}
//	if(thread->flag != SYS_NONE)
//	{
//		if(!(thread->flag == 3 && ((ret+1 == 0) || (ret == 0))))
//		if(thread->flag == SYS_OPEN && ret+1 != 0)
//		{
//			sprintf(buf[0], "/proc/self/fd/%d", (int)ret);
//			tmp = readlink(buf[0], buf[1], MAX_BUFSIZE);
//			buf[1][tmp] = '\0';
//
//			fstat((int)ret, &stat);
//
//			sprintf(buf[0],"%s:%lx:%x\n", buf[1], stat.st_size, (unsigned int)ret);
//			strcat(thread->buffer, buf[0]);
//		}
//		else
//		{
//			sprintf(buf[0],"%x\n", (unsigned int)ret);
//			strcat(thread->buffer, buf[0]);
//		}
//		fprintf(trace, "%s", thread->buffer);
//		fflush(trace);
//		thread->buffer[0] = '\0';
//		thread->flag = SYS_NONE;
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

//VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
//{
//	SysAfter(PIN_GetSyscallReturn(ctxt, std));
//}

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
		return;
	}
	PIN_RWMutexReadLock(&malloc_lock);
	node = FindAddressInRange(malloc_root, memaddr);
	PIN_RWMutexUnlock(&malloc_lock);
	if(node && node->usedforread == TRUE)
	{
//		fprintf(trace, "%x:%lx:%lx\n", MALLOC, memaddr, writesize);

		startoffset = memaddr - node->address + node->offset;
		endoffset = memaddr - node->address + node->offset + writesize;

		fprintf(trace, "%x%lx:%s:%lx:%lx:M\n", pid, node->readid, node->path, startoffset, endoffset);
		return;
	}
}

VOID StackWrite(ADDRINT memaddr, ADDRINT writesize)
{
	treeNode *node;
//	struct stat buf;
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	ADDRINT startoffset, endoffset;

	PIN_RWMutexReadLock(&thread_lock);
	struct thread* thread = FindThread(threadid);
	PIN_RWMutexUnlock(&thread_lock);

	node = FindAddressInRange(thread->stack, memaddr);
	if(node && node->usedforread == TRUE)
	{
//		fprintf(trace, "%x:%lx:%lx\n", STACK, memaddr, writesize);

		startoffset = memaddr - node->address + node->offset;
		endoffset = memaddr - node->address + node->offset + writesize;

//		stat(node->path, &buf);

		fprintf(trace, "%x%lx:%s:%lx:%lx:S\n", pid, node->readid, node->path, startoffset, endoffset);
	}
}

VOID Return(ADDRINT sp)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_RWMutexReadLock(&thread_lock);
	struct thread* thread = FindThread(threadid);
	PIN_RWMutexUnlock(&thread_lock);
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

//		// return value only available after
//		INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
//				IARG_SYSRET_VALUE,
//				IARG_END);
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

//	fprintf(trace, "%lx %x\n", PIN_ThreadUid(), PROCESSEND);
	fclose(trace);
}

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_RWMutexWriteLock(&thread_lock);
	root_thread = InsertThread(threadid, root_thread);
	PIN_RWMutexUnlock(&thread_lock);
}

VOID ThreadFini(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	PIN_THREAD_UID threadid = PIN_ThreadUid();
	PIN_RWMutexWriteLock(&thread_lock);
	root_thread = DeleteThread(threadid, root_thread);
	PIN_RWMutexUnlock(&thread_lock);
}

int main(int argc, CHAR *argv[])
{
    PIN_InitSymbols();

	pagesize = getpagesize();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    char *buf = (char*)malloc(sizeof(char)*200);
    assert(buf);

//    sprintf(buf, "trace_%x", getpid());

    int len = readlink("/proc/self/exe", buf, 200);
    buf[len] = '\0';
    int i;
    for(i=0; i<len; i++)
    {
    	if(buf[i] == '/')
    		buf[i] = '_';
    }

//    fprintf(stderr, "%s\n", buf);

    char *buf2 = (char*)malloc(sizeof(char)*200);

    sprintf(buf2, "/home/jungjae/pin-2.13-61206-gcc.4.4.7-linux/source/tools/MyPinTool/obj-intel64/log");

    strcat(buf2, buf);

    pid = getpid();
    sprintf(buf, "_%x", pid);

    strcat(buf2, buf);

    readid = 0;



    trace = fopen(buf2, "a");
//    fprintf(stderr, "%s\n", buf2);
//    perror("trace");
    assert(trace);

    free(buf);
    free(buf2);
    buf = NULL;
    buf2 = NULL;

	PIN_RWMutexInit(&malloc_lock);
	PIN_RWMutexInit(&thread_lock);
	PIN_RWMutexInit(&data_lock);
	PIN_MutexInit(&readid_lock);

    IMG_AddInstrumentFunction(ImageLoad, 0);

	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
//	PIN_AddSyscallExitFunction(SyscallExit, 0);
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

	PIN_RWMutexWriteLock(&malloc_lock);
	malloc_root = InsertMAddress(malloc_root, (ADDRINT)ret, size, 0);
	PIN_RWMutexUnlock(&malloc_lock);
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

/* ===================================================================== */

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

/* ===================================================================== */
/* eof */
/* ===================================================================== */
