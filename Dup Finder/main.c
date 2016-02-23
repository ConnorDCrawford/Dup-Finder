//
//  main.c
//  Dup Finder
//
//  Created by Connor Crawford on 11/10/15.
//  Copyright © 2015 Connor Crawford. All rights reserved.
//

#include <stdio.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#define SPACES_PER_INDENT_LEVEL 3
#define MAX_PATH_LENGTH 512

#define EXIT_USAGE_ERROR 1
#define EXIT_SUCCESS 0

struct Node{
    long key;
    int path_count;
    char *hash;
    char **paths;
    struct Node *left, *right;
};

long make_key(char hash[]);
void print_dups(struct Node *node);
void traverse_in_order(struct Node *, void (*func)(const void *));
//void init_hashtable(char **hashtable, int size);
//void deinit_hashtable(char **hashtable, int size);
void get_SHA1(FILE *fp, char str[]);
void to_hex_string(unsigned char bytes[], char str[], int len);
void usage(char**);
//void make_space(int num_spaces);
//int count_descendants(char *pathname, int depth, int count);
void digest_descendants(char *pathname, int depth, struct Node *node);
int is_dir(char * path_name);

//int hashtable_size;
//char **hashtable;
//char ***dups;
//int dup_count = 0;

int main(int argc, const char * argv[]) {
//    hashtable_size = count_descendants("/Users/connorcrawford/Downloads/untitled\ folder", 0, 0) * 2;
//    hashtable = malloc(sizeof(char*) * hashtable_size);
//    if (!hashtable)
//        return 1;
//    init_hashtable(hashtable, hashtable_size);
//    dups = malloc(sizeof(char *) * (hashtable_size/2));
    struct Node *root;
    digest_descendants("/Users/connorcrawford/Downloads/untitled\ folder", 0, root);
    
    traverse_in_order(root, &print_dups);
//    deinit_hashtable(hashtable, hashtable_size);
//    free(dups);
    return 0;
}

void print_dups(struct Node *node) {
    if (node && node->paths && node->path_count > 0) {
        int i;
        printf("Found %d duplicates of file ", node->path_count - 1);
        printf("%.*s\n", MAX_PATH_LENGTH, node->paths[0]);
        for (i = 1; i < node->path_count; i++) {
            
        }
    }
}

void traverse_in_order(struct Node *root, void (*func)(const void *)) {
    if (root != NULL) {
        if (func)
            func(root);
        traverse_in_order(root->left, func);
        traverse_in_order(root->right, func);
    }
}

long make_key(char hash[]) {
    int i;
    long key = 0;
    for (i = 0; i < sizeof(long); i++) {
        key += hash[i];
        key <<= 8;
    }
    return key;
}

static struct Node *new_node(char hash[], char path[]) {
    if (!hash) {
        return NULL;
    }
    struct Node *new = (struct Node*)malloc(sizeof(struct Node));
    if (!new)
        return NULL;
    new->key = make_key(hash);
    new->path_count = 1;
    new->hash = hash;
    new->paths = malloc(sizeof(char *));
    new->paths[0] = path;
    new->left = NULL;
    new->right = NULL;
    return new;
}

static struct Node *search_BST(struct Node *root, long *key) {
    if (root == NULL || root->hash == NULL)
        return NULL;
    if (root->key == *key)
        return root;
    if (*key < root->key)
        return search_BST(root->left, key);
    return search_BST(root->right, key);
}

static struct Node *insert_Node(struct Node *root, long *key, char hash[], char path[]) {
    if (!root)
        return new_node(hash, path);
    if (*key < root->key)
        root->left = insert_Node(root->left, key, hash, path);
    else if(*key > root->key)
        root->right = insert_Node(root->right, key, hash, path);
    return root;
}

void init_hashtable(char **hashtable, int size) {
    int i;
    for (i = 0; i < size; i++)
        hashtable[i] = NULL;
}

void deinit_hashtable(char **hashtable, int size) {
    int i;
    for (i = 0; i < size; i++)
        free(hashtable[i]);
    free(hashtable);
}

void get_SHA1(FILE *fp, char hash_as_str[]) {
    int c;
    unsigned char hash[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1_CTX ctx;
    CC_SHA1_Init(&ctx);
    
    while ((c=fgetc(fp))!=EOF) {
        CC_SHA1_Update(&ctx, &c, 1);
    }
    CC_SHA1_Final(hash, &ctx);
    to_hex_string(hash, hash_as_str, CC_SHA1_DIGEST_LENGTH);

}

/* fills str with a C-string version of the digest stored
 in bytes[] */
void to_hex_string(unsigned char bytes[], char str[], int len) {
    int i;
    for (i=0; i<len; i++) {
        sprintf(str, "%02X", (unsigned char)bytes[i]);
        str+=2;
    }
}


void usage(char **argv) {
    fprintf(stderr, "usage: %s filename\n", argv[0]);
}

/* returns 1 if path_name represents a directory
 0 if it isn't */
int is_dir(char *path_name) {
    struct stat buff;
    
    if (stat(path_name, &buff) < 0){
        fprintf(stderr, "stat: %s\n", strerror(errno));
        return 0;
    }
    
    return S_ISDIR(buff.st_mode);
}

//int count_descendants(char *pathname, int depth, int count) {
//    if (is_dir(pathname)) {
//        DIR *d;
//        struct dirent *p;
//        char path[MAX_PATH_LENGTH];
//        
//        if ((d = opendir(pathname)) == NULL){
//            fprintf(stderr, "opendir %s  %s\n", path, strerror(errno));
//            return -1;
//        }
//        
//        while ((p = readdir(d)) != NULL) {
//            if (strcmp(".", p->d_name)==0 || /* skip "." and ".." */
//                strcmp("..", p->d_name)==0)
//                continue;
////            make_space(depth*SPACES_PER_INDENT_LEVEL);
//            snprintf(path, MAX_PATH_LENGTH, "%s/%s", pathname, p->d_name);
//            count = count_descendants(path, depth+1, count + 1);
//        }
//        closedir(d);
//    }
//    return count;
//}

void digest_descendants(char *pathname, int depth, struct Node *root) {
    if (is_dir(pathname)) {
        DIR *d;
        struct dirent *p;
        char path[MAX_PATH_LENGTH];
        
        if ((d = opendir(pathname)) == NULL){
            fprintf(stderr, "opendir %s  %s\n", path, strerror(errno));
            return;
        }
        
        while ((p = readdir(d)) != NULL) {
            if (strcmp(".", p->d_name)==0 || /* skip "." and ".." */
                strcmp("..", p->d_name)==0)
                continue;
//            make_space(depth*SPACES_PER_INDENT_LEVEL);
            snprintf(path, MAX_PATH_LENGTH, "%s/%s", pathname, p->d_name);
//            printf("%s\n", p->d_name);
//            printf("%s\n", path);
            FILE *fp = fopen(path, "r");
            if (!fp)
                return;
            char hash_as_string[CC_SHA1_DIGEST_LENGTH*2+1];
            get_SHA1(fp, hash_as_string);
            
            // Store a copy of hash_as_string on heap
            char *m_hash_as_string = malloc(sizeof(char) * (CC_SHA1_DIGEST_LENGTH*2+1));
            if (!m_hash_as_string)
                return;
            strncpy(m_hash_as_string, hash_as_string, CC_SHA1_DIGEST_LENGTH*2+1);
            
            // Store a copy of path on heap
            char *m_path = malloc(sizeof(char) * MAX_PATH_LENGTH);
            if (!m_hash_as_string)
                return;
            strncpy(m_path, path, MAX_PATH_LENGTH);
            
            long key = make_key(m_hash_as_string);
            struct Node *search = search_BST(root, &key);
            if (!search) {
                if (!root)
                    root = insert_Node(root, &key, m_hash_as_string, m_path);
                else
                    insert_Node(root, &key, m_hash_as_string, m_path);
            } else {
                if (!strncasecmp(search->hash, m_hash_as_string, CC_SHA1_DIGEST_LENGTH*2+1)) {
                    
                    // Create new array of duplicates that is 1 greater than the size of search's old
                    char **new_dups = malloc(sizeof(char *) * (search->path_count + 1));
                    if (!new_dups) return;
                    
                    // Copy strings from old array into new
                    int i;
                    for (i = 0; i < search->path_count; i++) {
                        new_dups[i] = search->paths[i];
                        printf("%s\n", new_dups[i]);
                    }
                    
                    // Add new path to array of paths
                    new_dups[search->path_count] = m_path;
                    search->path_count++;
                    if (search->paths != NULL)
                        free(search->paths);
                    search->paths = new_dups;
                } else
                    insert_Node(root, &key, m_hash_as_string, m_path);
            }
//            if (hashtable[index] == NULL)
//                hashtable[index] = m_hash_as_string;
//            else {
//                char *hash= hashtable[index];
//                // Check if hashtable collision is a duplicate file by comparing SHA1 digests
//                if (strncasecmp(m_hash_as_string, hashtable[index], CC_SHA1_DIGEST_LENGTH) == 0) {
//                    char *m_path = malloc(sizeof(char) * MAX_PATH_LENGTH);
//                    strcpy(m_path, path);
//                    dups[dup_count++] = m_path;
//                }
//                
//                // Linear probing to find empty spot in hashtable if there is a collision
//                int i = index + 1;
//                while (hashtable[i] != NULL)
//                    i++;
//                hashtable[i] = m_hash_as_string;
//            }
            digest_descendants(path, depth+1, root);
        }
        closedir(d);
    }
}



//void make_space(int num_spaces) {
//    int i;
//    for (i=0; i<num_spaces; i++)
//        putchar(' ');
//}