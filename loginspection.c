#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define MAX_READ 10000
#define MAX_BUFSIZE	1024

typedef struct page
{
	int readid[MAX_READ];
	int count;
} PAGE;

typedef struct file
{
	char *path;
	PAGE **page;
	int size;

	struct file *left, *right;
} treeNode;
treeNode* file_root;

int pagesize;

void MakeInspection(void);
void ReadHandle(char* buf);
void StoreHandle(char* buf);
treeNode* InsertNode(treeNode *node, char* path, int startpage, int endpage, int filesizepage);
void Print(treeNode* node);

int main(void)
{
	pagesize = getpagesize();
	MakeInspection();
	Print(file_root);
	return 0;
}

/*
 * Print
 * Depth First Traverse and print the access info
 */
void Print(treeNode* node)
{
	if(node == NULL)
		return;

	Print(node->left);

	int i;
	int rcnt = 0;
	int dcnt = 0;
	printf("%s|", node->path);

	//cow
	for(i=0; i<=node->size; i++)
	{
		if(node->page[i] != NULL)
		{
			if(node->page[i]->count != 0)
			{
				printf("%d|", node->page[i]->count);
				dcnt++;
			}
			else
				printf("|");
		}
		else
			printf("|");
	}

	//read
	for(i=0; i<=node->size; i++)
	{
		if(node->page[i] != NULL)
		{
			rcnt++;
		}
	}
	printf("\nread page / total page = %d / %d (%.2f\%)|", rcnt, node->size+1, (double)rcnt*100 / (node->size+1));

	//read
	for(i=0; i<=node->size; i++)
	{
		if(node->page[i] != NULL)
		{
			printf("r|");
		}
		else
			printf("|");
	}
	printf("\ndup page / read page = %d / %d (%.2f\%)|", dcnt, rcnt, (double)dcnt*100 / rcnt);

	//file
	for(i=0; i<=node->size; i++)
	{
		printf("f|");
	}
	printf("\n");
	printf("\n");

	Print(node->right);
}

/*
 * MakeInspection
 * Read a line from log file and inspect it
 * Skip lines with bad format
 */
void MakeInspection()
{
	FILE *fp = fopen("log", "r");
	assert(fp);

	char buf[MAX_BUFSIZE];

	while(fgets(buf, MAX_BUFSIZE, fp) > 0)
	{

		int i = 0;
		int cnt = 0;
		while(buf[i] != '\n' && buf[i] != '\0')
		{
			if(buf[i] == ':')
				cnt++;
			i++;
		}
		if(cnt != 4)
			continue;
		if(buf[0] == '/')
		{
			//Read
			ReadHandle(buf);
		}
		else
		{
			//Store
			StoreHandle(buf);
		}
	}
	fclose(fp);
}

/*
 * ReadHandle
 * Parse Read log and add to BST
 */
void ReadHandle(char* buf)
{
	int i = 0;
	char path[MAX_BUFSIZE];
	long unsigned int offset, readsize, filesize;
	int startpage, endpage, filesizepage;

	if(buf[i] != '/')
		return;

	offset = 0;
	readsize = 0;
	filesize = 0;

	while(buf[i] != ':')
	{
		path[i] = buf[i];
		i++;
	}
	path[i] = '\0';
	i++;

	if(buf[i] == '/')
		return;

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			offset = offset*16 + (buf[i] - 'a' + 10);
		else
			offset = offset*16 + (buf[i] - '0');
		i++;
	}
	i++;

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			readsize = readsize*16 + (buf[i] - 'a' + 10);
		else
			readsize = readsize*16 + (buf[i] - '0');
		i++;
	}
	i++;

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			filesize = filesize*16 + (buf[i] - 'a' + 10);
		else
			filesize = filesize*16 + (buf[i] - '0');
		i++;
	}

	if(offset < 0 || readsize < 0 || filesize < 0)
		return;

	startpage = offset / pagesize;
	endpage = (offset+readsize) / pagesize;
	filesizepage = filesize / pagesize;

	assert(endpage <= filesizepage);
	if(startpage < 0)
		return;
	else if(endpage < 0)
		return;
	else if(filesizepage < 0)
		return;

	file_root = InsertNode(file_root, path, startpage, endpage, filesizepage);
}

/*
 * BST Functions
 */
treeNode* FindNode(treeNode *node, char* path)
{
	if(node==NULL)
	{
		/* Element is not found */
		return NULL;
	}

	int cmp = strcmp(node->path, path);

	if(cmp < 0)
	{
		/* Search in the right sub tree. */
		return FindNode(node->right,path);
	}
	else if(cmp > 0)
	{
		/* Search in the left sub tree. */
		return FindNode(node->left,path);
	}
	else
	{
		/* Element Found */
		return node;
	}
}

treeNode* InsertNode(treeNode *node, char* path, int startpage, int endpage, int filesizepage)
{
	if(node == NULL)
	{
		node = (treeNode*)malloc(sizeof(treeNode));
		assert(node);
		node->path = strdup(path);
		node->size = filesizepage;
		node->page = (PAGE**)malloc(sizeof(PAGE*)*(filesizepage+1));
		assert(node->page);
		memset(node->page, 0, sizeof(PAGE*)*(filesizepage+1));
		node->left = NULL;
		node->right = NULL;

		int i;
		for(i=startpage; i<=endpage; i++)
		{
			node->page[i] = (PAGE*)malloc(sizeof(PAGE));
			assert(node->page[i]);
			node->page[i]->count = 0;
		}
	}
	else
	{
		int cmp = strcmp(node->path, path);
		if(cmp > 0)
			node->left = InsertNode(node->left, path, startpage, endpage, filesizepage);
		else if(cmp < 0)
			node->right = InsertNode(node->right, path, startpage, endpage, filesizepage);
		else
		{
			if(node->size < filesizepage)
			{
				//If file size of later one, expand the data structure
				node->page = (PAGE**)realloc(node->page, sizeof(PAGE*)*(filesizepage+1));
				int j;
				for(j=node->size; j<=filesizepage; j++)
				{
					node->page[j] = NULL;
				}
				node->size = filesizepage;
			}
			int i;
			for(i=startpage; i<=endpage; i++)
			{
				if(node->page[i] == NULL)
				{
					node->page[i] = (PAGE*)malloc(sizeof(PAGE));
					assert(node->page[i]);
					node->page[i]->count = 0;
				}
			}
		}
	}
	return node;
}

void StoreHandle(char* buf)
{
	char path[MAX_BUFSIZE];
	int i = 0;
	int j = 0;
	int readid = 0;

	long unsigned int startoffset = 0, endoffset = 0;

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			readid = readid*16 + (buf[i] - 'a' + 10);
		else
			readid = readid*16 + (buf[i] - '0');
		i++;
	}
	i++;

	if(buf[i] != '/')
		return;

	while(buf[i] != ':')
	{
		path[j] = buf[i];
		i++;
		j++;
	}
	path[j] = '\0';
	i++;

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			startoffset = startoffset*16 + (buf[i] - 'a' + 10);
		else
			startoffset = startoffset*16 + (buf[i] - '0');
		i++;
	}
	i++;

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			endoffset = endoffset*16 + (buf[i] - 'a' + 10);
		else
			endoffset = endoffset*16 + (buf[i] - '0');
		i++;
	}
	i++;

	treeNode *file = FindNode(file_root, path);
	if(file == NULL)
		return;

	int startpage = startoffset / pagesize;
	int endpage = endoffset / pagesize;

	if(file->size <= endpage)
	{
		endpage = file->size;
	}
	i = startpage;

	if(startpage < 0)
		return;
	else if(startpage > endpage)
		return;

	NEXTLOOP:
	for(; i<=endpage; i++)
	{
		for(j=0; j<file->page[i]->count; j++)
		{
			if(file->page[i]->readid[j] == readid)
			{
				i++;
				goto NEXTLOOP;
			}
		}
		file->page[i]->readid[file->page[i]->count] = readid;
		file->page[i]->count++;
		assert(file->page[i]->count < MAX_READ);
	}
}
