#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define MAX_READ 1000
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

void Print(treeNode* node)
{
	if(node == NULL)
		return;

	Print(node->left);

	int i;
	printf("%s|", node->path);

	//cow
	for(i=0; i<=node->size; i++)
	{
		if(node->page[i] != NULL)
		{
			if(node->page[i]->count != 0)
				printf("%d|", node->page[i]->count);
			else
				printf("|");
		}
		else
			printf("|");
	}
	printf("\n|");

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
	printf("\n|");

	//file
	for(i=0; i<=node->size; i++)
	{
		printf("|");
	}
	printf("\n");

	Print(node->right);
}

void MakeInspection()
{
	FILE *fp = fopen("log", "r");
	assert(fp);

	char buf[MAX_BUFSIZE];

	while(fgets(buf, MAX_BUFSIZE, fp) > 0)
	{
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

void ReadHandle(char* buf)
{
	int i = 0;
	char path[MAX_BUFSIZE];
	long unsigned int offset, readsize, filesize;
	int startpage, endpage, filesizepage;

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

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			offset = offset*16 + (buf[i] - 'a');
		else
			offset = offset*16 + (buf[i] - '0');
		i++;
	}
	i++;

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			readsize = readsize*16 + (buf[i] - 'a');
		else
			readsize = readsize*16 + (buf[i] - '0');
		i++;
	}
	i++;

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			filesize = filesize*16 + (buf[i] - 'a');
		else
			filesize = filesize*16 + (buf[i] - '0');
		i++;
	}

	startpage = offset / pagesize;
	endpage = (offset+readsize) / pagesize;
	filesizepage = filesize / pagesize;

	file_root = InsertNode(file_root, path, startpage, endpage, filesizepage);
}

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
				PAGE** tmp = (PAGE**)malloc(sizeof(PAGE*)*(filesizepage+1));
				memset(tmp, 0, sizeof(PAGE*)*(filesizepage+1));
				memcpy(tmp, node->page, node->size+1);
				free(node->page);
				node->page = tmp;
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
			readid = readid*16 + (buf[i] - 'a');
		else
			readid = readid*16 + (buf[i] - '0');
		i++;
	}
	i++;

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
			readid = readid*16 + (buf[i] - 'a');
		else
			readid = readid*16 + (buf[i] - '0');
		i++;
	}
	i++;

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			startoffset = startoffset*16 + (buf[i] - 'a');
		else
			startoffset = startoffset*16 + (buf[i] - '0');
		i++;
	}
	i++;

	while(buf[i] != ':')
	{
		if(buf[i] >= 'a' && buf[i] <= 'z')
			endoffset = endoffset*16 + (buf[i] - 'a');
		else
			endoffset = endoffset*16 + (buf[i] - '0');
		i++;
	}
	i++;

	treeNode *file = FindNode(file_root, path);
	assert(file);

	int startpage = startoffset / pagesize;
	int endpage = endoffset / pagesize;

	if(file->size < endpage)
	{
		endpage = file->size;
	}
	i = startpage;

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
	}
}
