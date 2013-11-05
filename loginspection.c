/*
 * loginspection.c
 *
 *  Created on: Nov 4, 2013
 *      Author: jungjae
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#define TRUE	1
#define FALSE	0

#define MAX_BUFSIZE	1024

typedef struct openedfile
{
//	char path[MAX_BUFSIZE];
	char *path;
	long int size;

	int *cow_page;
	int pages;

	struct openedfile *left, *right;
} treeNode;
treeNode *file_root;

int pagesize;

void InsertLog();
void MakeFileTree();
treeNode * FindNode(treeNode *node, char* path);
treeNode* FindMinNode(treeNode *node);
treeNode* DeleteNode(treeNode *node, char* path);
treeNode* InsertNode(treeNode *root, treeNode *node);
treeNode* MakeNewNode(char* buf);

int main(void)
{
	pagesize = getpagesize();

	printf("makefiletree\n");
//	MakeFileTree();

	printf("insertlog\n");
	InsertLog();

	printf("printflog\n");
	treeNode *node = FindMinNode(file_root);

	while(node != NULL)
	{
		int offset;
		printf("%s|%d|", node->path, node->pages);
		for(offset = 0; offset < node->pages; offset++)
		{
			printf("%d|", node->cow_page[offset]);
		}
		printf("\n");
		file_root = DeleteNode(file_root, node->path);
		node = FindMinNode(file_root);
	}

	return 0;
}

void InsertLog()
{
	FILE *fp = fopen("cowlog", "r");
	assert(fp);

	char buf[2][MAX_BUFSIZE];
	treeNode *node;

	while(fgets(buf[0], MAX_BUFSIZE, fp) > 0)
	{
		int index = 0;

		while(buf[0][index+5] != ':')
		{
			buf[1][index] = buf[0][index+5];
			index++;
		}
		buf[1][index] = '\0';
//		fprintf(stderr, "%s\n", buf[1]);

		node = FindNode(file_root, buf[1]);
		if(node == NULL)
		{
			node = (treeNode*)malloc(sizeof(treeNode));
			assert(node);
			node->path = strdup(buf[1]);
			node->pages = 0;
			node->cow_page = (int*)malloc(sizeof(int));
			assert(node->cow_page);
			node->cow_page[0] = FALSE;
			node->size = 0;
			node->left = NULL;
			node->right = NULL;
			file_root = InsertNode(file_root, node);
		}
		assert(node);

		index = index + 6;

		long int startoffset = 0;
		long int endoffset = 0;

		while(buf[0][index] != ':')
		{
			if(buf[0][index] >= 'a' && buf[0][index] <= 'z')
				startoffset = startoffset*16 + (buf[0][index] - 'a');
			else
				startoffset = startoffset*16 + (buf[0][index] - '0');
			index++;
		}
		index++;

		while(buf[0][index] != ':' && buf[0][index] != '\n' && buf[0][index] != '\0')
		{
			if(buf[0][index] >= 'a' && buf[0][index] <= 'z')
				endoffset = endoffset*16 + (buf[0][index] - 'a');
			else
				endoffset = endoffset*16 + (buf[0][index] - '0');
			index++;
		}

		int pageoffset = startoffset / pagesize;
		while(1)
		{
			if(pageoffset >= node->pages)
			{
				node->cow_page = (int*)realloc(node->cow_page, sizeof(int)*(pageoffset+1));
				assert(node->cow_page);
				memset(node->cow_page+node->pages+1, 0, pageoffset - node->pages);
				node->pages = pageoffset;
			}

			assert(node->cow_page);
//			fprintf(stderr, "%s %d %d\n", node->path, node->pages, pageoffset);
			node->cow_page[pageoffset] = TRUE;
			pageoffset = pageoffset + 1;
			if(pageoffset * pagesize > endoffset)
				break;
		}
	}

	fclose(fp);
}

void MakeFileTree()
{
	FILE *fp = fopen("openlog", "r");
	assert(fp);

	char buf[MAX_BUFSIZE];
	treeNode *node;

	while(fgets(buf, MAX_BUFSIZE, fp) > 0)
	{
		node = MakeNewNode(buf);
//		fprintf(stderr, "%s\n", node->path);
//		file_root = DeleteNode(file_root, node->path);
		file_root = InsertNode(file_root, node);
	}

	fclose(fp);
}

treeNode * FindNode(treeNode *node, char* path)
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

treeNode* FindMinNode(treeNode *node)
{
	if(node==NULL)
	{
		/* There is no element in the tree */
		return NULL;
	}
	if(node->left) /* Go to the left sub tree to find the min element */
		return FindMinNode(node->left);
	else
		return node;
}

treeNode* DeleteNode(treeNode *node, char* path)
{
	if(node == NULL)
		return NULL;
	int cmp = strcmp(node->path, path);
	if(cmp > 0)
	{
		node->left = DeleteNode(node->left, path);
	}
	else if(cmp < 0)
	{
		node->right = DeleteNode(node->right, path);
	}
	else
	{
		/* Now We can delete this node and replace with either minimum element
                   in the right sub tree or maximum element in the left subtree */
		treeNode *temp;
		if(node->right && node->left)
		{
			/* Here we will replace with minimum element in the right sub tree */
			temp = FindMinNode(node->right);

//			if(node->cow_page != NULL)
//				free(node->cow_page);
			node->cow_page = temp->cow_page;
//			temp->cow_page = NULL;
//			if(node->path != NULL)
//				free(node->path);
			node->path = temp->path;
//			temp->path = NULL;

			node->size = temp->size;

			/* As we replaced it with some other node, we have to delete that node */
			node -> right = DeleteNode(node->right,node->path);
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
//			if(temp->path != NULL)
//				free(temp->path);
//			if(temp->cow_page != NULL)
//				free(temp->cow_page);
			free(temp); /* temp is longer required */
		}
	}
	return node;
}

treeNode* InsertNode(treeNode *root, treeNode *node)
{
	if(root == NULL)
		return node;
	else
	{
		int cmp = strcmp(root->path, node->path);
		if(cmp > 0)
			root->left = InsertNode(root->left, node);
		else if(cmp < 0)
			root->right = InsertNode(root->right, node);
		else
		{
			free(node->cow_page);
			free(node->path);
			free(node);
		}

		return root;
	}
}

treeNode* MakeNewNode(char* buf)
{
	int index;
	int count;
	char path[MAX_BUFSIZE];
	treeNode *node = (treeNode*)malloc(sizeof(treeNode));
	if(node == NULL)
		exit(-1);

	index = 0;
	while(buf[index+2] != '|')
	{
		path[index] = buf[index+2];
		index++;
	}
	path[index] = '\0';

	node->path = strdup(path);

	index = index + 3;

	node->size = 0;
	while(buf[index] != '|')
	{
		if(buf[index] >= 'a' && buf[index] <= 'z')
			node->size = node->size*16 + (buf[index] - 'a');
		else
			node->size = node->size*16 + (buf[index] - '0');
		index++;
	}

	node->pages = node->size / pagesize;
	node->cow_page = (int*)calloc(node->pages+1, sizeof(int));

	node->left = NULL;
	node->right = NULL;

	return node;
}
