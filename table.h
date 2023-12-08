#define _GNU_SOURCE

//################################################
//### Hash table implementation using seatch.h ###
//################################################

#include <search.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "sha256.h"

#ifndef TABLE_H
#define TABLE_H

//Structure for holding the data of each table entry
typedef struct table_data {
    size_t size;
    SHA256_CTX* ctx;
} table_data_t;

//Structure for the encompasing table itself
typedef struct table_t {
    struct hsearch_data htab;
    size_t size;
    char ** keys;
} table_t;

//Helper for getting an entry in the table given a key pointer
table_data_t* table_get(table_t* table, char* key) {
    //Setup entry struct
    ENTRY entry, *entry_ptr;
    entry.key = key;
    //use search.h hsearch to find the value for the given key
    int result = hsearch_r(entry, FIND, &entry_ptr, &table->htab);
    if (!result) {
        //No result was found
        return NULL;
    }
    //Cast the result data pointer
    return (table_data_t*) entry_ptr->data;
}

//Helper for allocating and setting up a table structure
table_t* table_create(size_t size) {
    table_t* table = malloc(sizeof (*table));
    //Initialize members
    table->htab = (struct hsearch_data){0};
    table->size = 0;
    //Setting up table in search.h
    hcreate_r(size, &table->htab);
    table->size = size;
    //Allocate keys
    int ks = size * sizeof (char *);
    table->keys = malloc(ks);
    //Make sure the allocated memory is set to 0
    memset(table->keys, 0, ks);
    return table;
}

//Function to properly destory the table by unallocating all entries along with the table itself
void table_destroy(table_t* table) {
    //Loop over all table entries
    for (int i = 0; i < table->htab.filled; ++i) {
        table_data_t * table_data = table_get(table, table->keys[i]);
        //If we have a table data entry with no data bail as this is not a valid state
        assert(dt && "no data in table_data_t!");
        if (table_data->ctx) { //If table data ctx pointer isn't null, Unallocate it
            free(table_data->ctx);
        }
        free(dt); //Unallocate the table data pointer itself
        free(table->keys[i]); //Unallocated each table key
    }
    free(table->keys); //Unallocate the keys itself
    //Unallocate the table structure and destory it within search.h
    hdestroy_r(&table->htab);
    free(table);
    table = NULL;
}

//Helper for inserting an entry into the table given a table_data_t
int table_add(table_t* table, char* key, table_data_t * data) {
    //Setup search.h entry struct
    ENTRY entry, *entry_ptr;
    entry.key = strdup(key);
    entry.data = data;
    int filled = table->htab.filled;
    //Search the table for the given entry and its key
    int result = hsearch_r(entry, ENTER, &entry_ptr, &table->htab);
    if (filled < table->htab.filled) {
        //assert the table capacity is large enough for this operation and crash if not
        assert(table->keys[filled] == 0 && "Out of space!");
        *(table->keys + filled) = entry.key;
    } else {
        //Cannot overrite the current "block"
        assert(0 && "Cannot overwrite!");
    }
    return result;
}
#endif