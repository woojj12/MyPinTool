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
#include <iostream>
#include <fstream>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

using namespace std;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

PIN_MUTEX thread_lock, malloc_lock, data_lock;

FILE *fp;

typedef VOID * (*FUNCPTR_MALLOC)(size_t);
typedef VOID * (*FUNCPTR_REALLOC)(void*, size_t);

//VOID ReplaceJitted( RTN rtn, PROTO proto_malloc );
VOID * Jit_Malloc_IA32( CONTEXT * context, AFUNPTR orgFuncptr, size_t arg0 );
VOID * Jit_Realloc_IA32( CONTEXT * context, AFUNPTR orgFuncptr, void * ptr, size_t arg0 );
VOID   Jit_Free_IA32( CONTEXT * context, AFUNPTR orgFuncptr, void * arg0 );
VOID   Jit_Exit_IA32( CONTEXT * context, AFUNPTR orgFuncptr, int code );

/*
 *
 */

typedef struct treeNode
{
	OS_THREAD_ID threadid;

	ADDRINT address;
	ADDRINT size;
	BOOL usedforread;

	struct treeNode *left;
	struct treeNode *right;

}treeNode;

treeNode *malloc_root;//, *stack_root;

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

treeNode * InsertMAddress(treeNode *node, ADDRINT address, ADDRINT size)
{
	if(node==NULL)
	{
		treeNode *temp;
		temp = (treeNode *)malloc(sizeof(treeNode));
		assert(temp);
		temp -> threadid = PIN_GetTid();
		temp -> address = address;
		temp -> size = size;
		temp -> usedforread = FALSE;
		temp -> left = temp -> right = NULL;
	    fprintf(fp, "%x malloc %lx %lx\n", PIN_GetTid(), size, address);
		return temp;
	}

	if(address >(node->address))
	{
		node->right = InsertMAddress(node->right,address,size);
	}
	else if(address < (node->address))
	{
		node->left = InsertMAddress(node->left,address,size);
	}
	else
	{
		fprintf(stderr, "%x %lx %lx\n", PIN_GetTid(), address, size);
//		assert(0);
		if(node->size == size && node->address == address && node->threadid == PIN_GetTid())
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
		assert(0);
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
    	fprintf(fp, "%x free %lx\n", PIN_GetTid(), address);
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

//ofstream TraceFile;

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
            mallocRtn, AFUNPTR( Jit_Malloc_IA32 ),
            IARG_PROTOTYPE, proto_malloc,
            IARG_CONTEXT,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_CALL_ORDER, CALL_ORDER_FIRST,
            IARG_END);

//        TraceFile << "Replaced malloc() in:"  << IMG_Name(img) << endl;
//        fprintf(fp, "Replaced malloc() in %s\n", IMG_Name(img).c_str());
    }

    RTN reallocRtn = RTN_FindByName(img, "realloc");
    if (RTN_Valid(reallocRtn))
    {
        PROTO proto_realloc = PROTO_Allocate( PIN_PARG(void *), CALLINGSTD_DEFAULT,
                                             "realloc", PIN_PARG(void *), PIN_PARG(size_t), PIN_PARG_END() );

        RTN_ReplaceSignature(
            reallocRtn, AFUNPTR( Jit_Realloc_IA32 ),
            IARG_PROTOTYPE, proto_realloc,
            IARG_CONTEXT,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
            IARG_CALL_ORDER, CALL_ORDER_FIRST+1,
            IARG_END);

//        TraceFile << "Replaced realloc() in:"  << IMG_Name(img) << endl;
//        fprintf(fp, "Replaced realloc() in %s\n", IMG_Name(img).c_str());
    }

    RTN freeRtn = RTN_FindByName(img, "free");
    if (RTN_Valid(freeRtn))
    {
        PROTO proto_free = PROTO_Allocate( PIN_PARG(void), CALLINGSTD_DEFAULT,
                                           "free", PIN_PARG(void *), PIN_PARG_END() );

        RTN_ReplaceSignature(
            freeRtn, AFUNPTR( Jit_Free_IA32 ),
            IARG_PROTOTYPE, proto_free,
            IARG_CONTEXT,
            IARG_ORIG_FUNCPTR,
            IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
            IARG_CALL_ORDER, CALL_ORDER_FIRST+2,
            IARG_END);

//        TraceFile << "Replaced free() in:"  << IMG_Name(img) << endl;
//        fprintf(fp, "Replaced free() in %s\n", IMG_Name(img).c_str());
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
	fclose(fp);
	PIN_MutexFini(&malloc_lock);
}

int main(int argc, CHAR *argv[])
{
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }

    char *buf = (char*)malloc(sizeof(char)*100);
    assert(buf);

    sprintf(buf, "trace_%x", getpid());

    fp = fopen(buf, "a");

    free(buf);
    buf = NULL;

	PIN_MutexInit(&malloc_lock);

    IMG_AddInstrumentFunction(ImageLoad, 0);

	PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}


/* ===================================================================== */

VOID * Jit_Malloc_IA32( CONTEXT * context, AFUNPTR orgFuncptr, size_t size)
{
    VOID * ret;

    PIN_CallApplicationFunction( context, PIN_ThreadId(),
                                 CALLINGSTD_DEFAULT, orgFuncptr,
                                 PIN_PARG(void *), &ret,
                                 PIN_PARG(size_t), size,
                                 PIN_PARG_END() );

	PIN_MutexLock(&malloc_lock);
	malloc_root = InsertMAddress(malloc_root, (ADDRINT)ret, size);
	PIN_MutexUnlock(&malloc_lock);
    return ret;
}

/* ===================================================================== */

VOID * Jit_Realloc_IA32( CONTEXT * context, AFUNPTR orgFuncptr, void * ptr, size_t size)
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
			malloc_root = DeleteAddress(malloc_root, (ADDRINT)ptr);
			malloc_root = InsertMAddress(malloc_root, (ADDRINT)ret, size);
    	}
    }
	PIN_MutexUnlock(&malloc_lock);
    return ret;
}

/* ===================================================================== */

VOID Jit_Free_IA32( CONTEXT * context, AFUNPTR orgFuncptr, void * ptr)
{
    if(ptr != NULL)
    {
		PIN_MutexLock(&malloc_lock);
		malloc_root = DeleteAddress(malloc_root, (ADDRINT)ptr);
		PIN_MutexUnlock(&malloc_lock);
//    	fprintf(fp, "%x free %p\n", PIN_GetTid(), ptr);
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
