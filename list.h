#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#########################################
//### Double linked list implementation ###
//#########################################

#ifndef LIST_H
#define LIST_H

typedef struct node_t node_t;
//Structure for each node in the double linked list holding a string pointer
struct node_t {
    char* data;
    struct node_t* next;
    struct node_t* prev;
};

//Main structure for the list itself holding the head and tail nodes
typedef struct list {
    node_t* head;
    node_t* tail;
    int size;
} list_t;

//Helper for creating and allocating the list structure
list_t* list_create() {
    //Allocate the encompasing list struct
    list_t* list = malloc(sizeof(list_t));
    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
    return list;
}

//Helper for creating a node and appending it properly to the linked list
void list_append(list_t* list, char* data) {
    //Always make a copy of the string being appended to the list to avoid any accidental pointer alisasing overrites
    char* str = strdup(data);

    //Allocate the new node
    node_t* new_node = malloc(sizeof(node_t));
    new_node->data = str;
    new_node->next = NULL;

    //Initially, if the list is empty, the head and tail point to the same node
    if (list->head == NULL) {
        list->head = new_node;
    } else { //Only set prev is the list is NOT empty
        //Fix the chain to now point to this node
        list->tail->next = new_node;
        //keep track of the old tail to use as the prev node for the new tail
        new_node->prev = list->tail;
    }

    //Assign a new tail node and increase the list size
    list->tail = new_node;
    list->size++;
}

//Helper for destroying the list and unallocating all the pointers
void list_destroy(list_t* list) {
    //Start with the head node
    node_t* cur = list->head;
    
    //Loop until next no longer points to a valid pointer
    while (cur != NULL) {
        //Free the string in the node
        free(cur->data);
        
        //Assign next to the next node in the linked list
        cur = cur->next;

        //Make sure we're not at the end of the list before trying to remove prev
        if (cur != NULL) {
            //Free the previous node now that we have a reference to the next in the chain
            if (cur->prev != NULL) {
                free(cur->prev);
            }
        } else { // if we are, remove cur    
            free(cur);
        }
    }

    //Free the list pointer itself
    free(list);
}
#endif