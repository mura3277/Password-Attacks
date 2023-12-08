#include "table.h"
#include "list.h"
#include "sha256.h"
#include <time.h>

//##########################
//### Global allocations ###
//##########################

//For storing found passwords and their hashes
char* passwordHashes[10];
char* passwordStrings[10];
//For keeping track how many passwords were found
int nextPasswordIndex = 0;
//How many targets each task is trying to find
int targetLength = 0;

BYTE buf[SHA256_BLOCK_SIZE];

//###############################
//### Sha256 helper functions ###
//###############################

//Helper for converting the resulting byte array from sha256_finalize to a hex hash string
char* byte_array_to_hex_string(BYTE arr[]) {
    char *s = malloc(SHA256_BLOCK_SIZE * 2 + 1);
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        sprintf(s + i * 2, "%02x", arr[i]);
    }
    return s;
}

//Helper for calling sha256_update
void update_sha_ctx(SHA256_CTX* ctx, char* append) {
    sha256_update(ctx, append, strlen(append));
}

//Helper for constructing a new sha256 context with the option of passing an initial string
SHA256_CTX* construct_sha_ctx(char* initial) {
    SHA256_CTX* ctx = malloc(sizeof(SHA256_CTX));
    sha256_init(ctx);
    if (initial != NULL) {
        update_sha_ctx(ctx, initial);
    }
    return ctx;
}

//Use memcpy to copy an existing sha256 instance instead of creating one from scratch and computing the underlying hash result all over again (this should be pretty fast)
SHA256_CTX* copy_sha_ctx(SHA256_CTX* ctx) {
    //Allocate new copy
    SHA256_CTX* new = malloc(sizeof(SHA256_CTX));
    //Set values from existing to copy
    memcpy(&new->data, &ctx->data, sizeof(ctx->data));
    memcpy(&new->state, &ctx->state, sizeof(ctx->state));
    memcpy(&new->datalen, &ctx->datalen, sizeof(ctx->datalen));
    memcpy(&new->bitlen, &ctx->bitlen, sizeof(ctx->bitlen));
    return new;
}

//Helper to finalize the sha256 context then create and pass a buffer for printing
char* finalize_sha_ctx(SHA256_CTX* ctx) {
    sha256_final(ctx, buf);
    return byte_array_to_hex_string(buf);
}

//Helper function to print the result of the sha256 context as a hex string
void copy_and_print_sha(char* prefix, SHA256_CTX* ctx) {
    SHA256_CTX* copy = copy_sha_ctx(ctx);
    char* hex = finalize_sha_ctx(copy);
    printf("%s", prefix);
    printf("%s\n", hex);
    free(hex); //Free the allocated string from byte_array_to_hex_string
    free(copy); //Free the copy of the sha256_ctx
}

//##################################
//### Hashtable helper functions ###
//##################################

//Helper for adding a sha256 context to a hash table
void add_ctx_to_table(table_t* table, SHA256_CTX* ctx, char* s) {
    table_data_t * data = malloc(sizeof (table_data_t)); //No need to free this pointer as that's handled by table_destroy
    data->ctx = ctx;
    int result = table_add(table, s, data);
    if (result == 0) {
        fprintf(stdout, "ERROR INSERTING!");
        exit(1);
    }
}

//##############################################
//### Implementation functions for all tasks ###
//##############################################

//Check if the hash is in our target list, and if so, add it to the password dictionary with the corresponding plain-text input
void check_hash(char** targets, char** salts, SHA256_CTX* new_hash, char* s) {
    SHA256_CTX* copy_hash = copy_sha_ctx(new_hash);
    char* hex = finalize_sha_ctx(copy_hash); //This allocation from byte_array_to_hex_string is freed when passwordStrings is cleaned by the cleanup function
    free(copy_hash); //Free the copy of new_hash used just to finalize and obtain the hex
    SHA256_CTX* temp_hash = NULL;

    for (int i = 0; targets[i] != NULL; i++) {
        //Only regenerate the hex if we are passed a list of salts as this needs to be done for every target+salt pair
        if (salts != NULL) {
            //Make a copy of the unsalted new_hash so we can preserve it for the next iteration
            temp_hash = copy_sha_ctx(new_hash);
            //Update the current hex iteration with the now salted hash for the current target
            update_sha_ctx(temp_hash, salts[i]);
            //Update the new hex value to check against
            hex = finalize_sha_ctx(temp_hash);
            //Finall free the temp_hash allocation
            free(temp_hash);
        }

        //hex and the current i'th target are equal
        if (strcmp(hex, targets[i]) == 0) {
            //Add the found password!
            passwordHashes[nextPasswordIndex] = hex;
            char* pass = strdup(s); //This allocation is freed by cleanup
            passwordStrings[nextPasswordIndex] = pass;
            nextPasswordIndex++;
            return;
        }
    }

    //if we reach this point, check_hash did not find anything and we must free the pointer to hex, as its reference will be lost
    free(hex);
}

//Find x, which is the input s shortened by 1 character by each iteration so we can query an existing hash object
char* find_prev_hash_input(table_t* hashes, char* s) {
    int len = strlen(s);
    //Construct x which is one character shorter for every iteration
    char* x = malloc(sizeof(char) * 32);
    for (int i = 1; i <= len - 1; i++) {
        strncpy(x, s, len - i);
        x[len - i] = '\0';
        
        //Check if the result of x has alreary been computer by a previous iteration
        if (table_get(hashes, x) != NULL) {
            return x;
        }
    }
    //If we reach this point no previous hash matches were found and x must be freed as it will no longer have a reference
    free(x);
    return NULL;
}

//Build a sha256 hash for a given input s by building upon previously created context objects and updating instead of creating new ones from scratch
SHA256_CTX* build_hash(table_t* hashes, char* s) {
    SHA256_CTX* new_hash;

    //Get a previous hash input, if it exists
    char* x = find_prev_hash_input(hashes, s);

    //If no previous hash was found, create one from scratch
    if (x == NULL) {
        new_hash = construct_sha_ctx(s);
    } else {
        table_data_t* result = table_get(hashes, x);
        SHA256_CTX* prev = result->ctx;

        //Update the value of the hash for s by only selecting the "new" characters that are in addition to the value of x
        char y[32];
        int prev_len = strlen(x);
        strncpy(y, &s[prev_len], strlen(s));

        //Make a copy as to not mutate existing dictionary entries
        new_hash = copy_sha_ctx(prev);

        //Update the hash with the new characters
        update_sha_ctx(new_hash, y);

        //Finall make sure to feee the allocated x string
        free(x);
    }

    //We should now have a starting hash object, either computed from scratch or starting from a previous chunk of input s
    //Finally insert this new hash into the dictonary for the next iteration
    add_ctx_to_table(hashes, new_hash, s);

    return new_hash;
}

//Used by Task 2 and 3 to brute force the passwords with a dictionary attack
int brute_force(char** targets, char** salts, table_t* hashes, char* s) {
    //Check the current string line against the target hashes
    SHA256_CTX* new_hash = build_hash(hashes, s);
    //Check if the hash is valid
    check_hash(targets, salts, new_hash, s);

    //If all passwords found, break early and do not check for longer passwords
    if (nextPasswordIndex == targetLength) {
        return 1;
    } else {
        return 0;
    }
}

//Helper function to call a function pointer for every line in a given file
void iterateFile(char* filename, char** targets, char** salts, table_t* hashes, int (*FUNC)(char**, char**, table_t*, char*)) {
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    //Open the file and throw error if this cannot be done
    fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stdout, "Cannot open file!");
        exit(1);
    }
    //While we haven't reached the end of the file, file the pointer to line with the result of getline()
    while ((read = getline(&line, &len, fp)) != -1) {
        int len_line = strlen(line);
        //Strip the new line characters
        if (line[len_line - 1] == '\n') {
            line[len_line - 1] = '\0';
        }
        //Call the function pointer passed to this function
        int result = FUNC(targets, salts, hashes, line);
        //If the function returns 1 then all targets have been found and we can break out of the loop early
        if (result == 1) {
            break;
        }
    }
    //Close file and ree allocations
    fclose(fp);
    if (line) {
        free(line);
    }
}

//Helper function to check if a string ends with a substring
int string_ends_with(const char * str, const char * suffix) {
    //Get both lens
    int str_len = strlen(str);
    int suffix_len = strlen(suffix);
    //Return 1 (true) if str ends with suffix
    if ((str_len >= suffix_len) && (strcmp(str + (str_len-suffix_len), suffix) == 0)) {
        return 1;
    } else {
        return 0;
    }
}

//Iterate over all possible characters using shortlex ordering
list_t* iterate_all_inputs(table_t* hashes, char** targets, char* valid_chars, int cur_len, int max_len) {
    //Allocate the list to keep track of the results to return up the recursive call stack
    list_t* result = list_create();

    //If we recurse down to a cur_len of 0, then the prev_result for the parent function call should be empty
    if (cur_len == 0) {
        list_append(result, "");
        return result;
    }

    //Recirsevely call iterate_all_inputs, decrementing cur_len each time until we get to 0, appending the result to a list
    list_t* list = iterate_all_inputs(hashes, targets, valid_chars, cur_len - 1, max_len);

    //Reference to initial head node
    node_t* next = list->head;
    char* prev_result;
    //Loop through all nodes 
    while (next != NULL) {
        //Nested loop to iterate through every char in our valid_chars list
        char cur_char;
        for (int i = 0; i < strlen(valid_chars); i++) {
            cur_char = valid_chars[i];

            //Construct a string chuck of the max_len of the cur_char, eg: aaaa if max_len = 4
            char ending_check[max_len + 1];
            for (int j = 0; j < max_len; j++) {
                ending_check[j] = cur_char;
            }
            ending_check[max_len] = '\0'; //Don't forget this!

            char* prev_result = next->data;
            //If the prev_result already ends with the max len of cur_char, skip it
            if (string_ends_with(prev_result, ending_check) == 0) {
                //Build the result string with the previous recursion and cur_char and append it to our result list
                //Combine prev_result and cur_char. Create buffer with size of both plus trailing \0
                char s[strlen(prev_result) + 2]; //len(prev_result) + cur_char + '\0'
                strcpy(s, prev_result);
                s[strlen(prev_result)] = cur_char;
                s[strlen(prev_result) + 1] = '\0'; //Don't forget this!
                list_append(result, s); //list_append makes a copy so s can be unallocated safely by the scope finishing

                //Check the current string s against the target hashes
                SHA256_CTX* new_hash = build_hash(hashes, s);

                //#Check if the hash is valid
                check_hash(targets, NULL, new_hash, s);

                //If all passwords found, break early and do not check for longer passwords
                if (nextPasswordIndex == targetLength) {
                    return result;
                }
            }
        }

        //Jump to the next node in the list
        next = next->next;
    }

    //Unallocate the previous recursed function call list result
    list_destroy(list);

    return result;
}

//###########################
//### Main task functions ###
//###########################

//Routines for task 1
char** task1(char** targets, int size) {
    //table for storing hash objects. must be 60,000 in size for task 1
    table_t* hashes = table_create(60000);

    //Build list of valud input characters for the algorithm to check against
    char* valid_chars = "abcdefghijklmnopqrstuvwxyz0123456789";

    //Call the recursive iteration function to check every permutation of possible input characters, given targets and a max size
    list_t* result = iterate_all_inputs(hashes, targets, valid_chars, size, size);
    //Unallocate the final resulting list
    printf("size: %i\n", result->size);
    list_destroy(result);

    //Destroy the table for storing previous hashes to free up memory
    table_destroy(hashes);

    return passwordStrings;
}

//Routines for task 2
char** task2(char** targets) {
    //Create an appropriately sized table for the previous hash objects
    table_t* hashes = table_create(7000);

    //For every line in the dictionary, check if the hash exists in targets
    iterateFile("PasswordDictionary.txt", targets, NULL, hashes, brute_force);

    //Destroy the table for storing previous hashes to free up memory
    table_destroy(hashes);
    
    return passwordStrings;
}

//Routines for task 3
char** task3(char** targets, char** salts) {
    //Create an appropriately sized table for the previous hash objects
    table_t* hashes = table_create(7000);

    //For every line in the dictionary, check if the hash exists in targets
    iterateFile("PasswordDictionary.txt", targets, salts, hashes, brute_force);
    
    //Destroy the table for storing previous hashes to free up memory
    table_destroy(hashes);

    return passwordStrings;
}

//Helper to clean up after each task runs
void cleanup() {
    //Free the allocated password pointers
    for (int i = 0; i < 10; i++) {
        free(passwordStrings[i]);
        free(passwordHashes[i]);
    }
    //Set all their values to 0
    memset(passwordHashes, 0, sizeof(passwordHashes));
    memset(passwordStrings, 0, sizeof(passwordStrings));
    //Reset password index for the next task
    nextPasswordIndex = 0;
}

//Helper function that prints the password strings along with their hash hex pair
void print_passwords(char** passwords) {
    for (int i = 0; i < nextPasswordIndex; i++) {
        printf("%s - %s\n", passwords[i], passwordHashes[i]);
    }
}

//###########################
//### Program entry point ###
//###########################

int main(int argc, char* argv[]) {
    clock_t start = clock();

    //Task 1
    printf("\n");
    printf("############################\n");
    printf("############################\n");
    printf("Starting Task 1...\n");

    char* targets1[] = {
        "594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06",
        "ade5880f369fd9765fb6cffdf67b5d4dfb2cf650a49c848a0ce7be1c10e80b23",
        "83cf8b609de60036a8277bd0e96135751bbc07eb234256d4b65b893360651bf2",
        "0d335a3bea76dac4e3926d91c52d5bdd716bac2b16db8caf3fb6b7a58cbd92a7",
        NULL //Append a null pointer to the list of targets to detect when we no longer have any more values to iterate over
    };
    targetLength = 4;

    clock_t task1_start = clock();
    char** passwords1 = task1(targets1, 4);
    clock_t task1_stop = clock();
    double task1_elapsed = (double)(task1_stop - task1_start) * 1000.0 / CLOCKS_PER_SEC;
    print_passwords(passwords1);
    //If the amount of passwords added to the passwordStrings array equals the number of targets, we found all passwords!!
    if (nextPasswordIndex == targetLength) {
        printf("@@@ FOUND ALL TASK 1 PASSWORDS @@@\n");
    }
    printf("@@@ FINISHED TASK 1 IN %fms @@@\n", task1_elapsed);
    //Reset global variables
    cleanup();

    printf("############################\n");
    printf("############################\n");
    printf("\n");
    printf("\n");

    //Task 2
    printf("############################\n");
    printf("############################\n");
    printf("Starting Task 2...\n");

    char* targets2[] = {
        "1a7648bc484b3d9ed9e2226d223a6193d64e5e1fcacd97868adec665fe12b924",
        "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
        "48054a90032bf1348452fd74f3500ef8d2318d9b5582b07449b3b59db841eecd",
        "09537eae89936399905661760584b19f6ff3af4bb807cee0bb663f64b07eea8e",
        "e7798dc61be73b717402d76cbfaaef41c36c85c027a59abd74abbc8c8288bd4f",
        "0f42bcbeedf89160a6cf7ccafe68080f2aafb73b3ef057df6b5e22f1294d0a10",
        "13989fe9c124d4dfca4e2661dcf8449f49a76fb69f9725612a130622ff3f9bfb",
        "d780c9776eb7d602c805af9ed7aa78225b36af0decb6be51045dcbfa661594a3",
        "d2d03c10a4f2c361dbeff74dab0019264e37336f9ef04831943d0f07c0ad52c7",
        "cbb05a10a2fc5cc96ce5da00a12acc54f594eadb85363de665f3e5dcb81d0e51",
        NULL //Append a null pointer to the list of targets to detect when we no longer have any more values to iterate over
    };
    targetLength = 10;
    clock_t task2_start = clock();
    char** passwords2 = task2(targets2);
    clock_t task2_stop = clock();
    double task2_elapsed = (double)(task2_stop - task2_start) * 1000.0 / CLOCKS_PER_SEC;
    print_passwords(passwords2);
    //If the amount of passwords added to the passwordStrings array equals the number of targets, we found all passwords!!
    if (nextPasswordIndex == targetLength) {
        printf("@@@ FOUND ALL TASK 2 PASSWORDS @@@\n");
    }
    printf("@@@ FINISHED TASK 2 IN %fms @@@\n", task2_elapsed);
    //Reset global variables
    cleanup();

    printf("############################\n");
    printf("############################\n");
    printf("\n");
    printf("\n");

    //Task 3
    printf("############################\n");
    printf("############################\n");
    printf("Starting Task 3...\n");

    char* targets3[] = {
        "915edb4d39ab6d260e3fb7269f5d9f8cfba3fdc998415298af3e6eb94a82e43e",
        "5ddce1dc316e7914ab6af64ef7c00d8b603fac32381db963d9359c3371a84b3a",
        "7e3b02bacd934245aa0cb3ea4d2b2f993a8681a650e38a63175374c28c4a7d0d",
        "d3136c0cb931acc938de13ed45926eb8764f9ea64af31be479be157480fd3014",
        "3a9053a077383d11f5963ef0c66b38c7eb8331cdb03bbdcc0e5055307f67331b",
        "59c05d8d7b6d29279975141f7329cd77a5dc6942b036f9dfd30cbcb52c320cb4",
        "c93802a2273a13c2b8378f98dda9f166783cbfce508aeaf570ad0b19a906b4d2",
        "e6a9713791c2ffeddbf6c6c395add47e1fc02ae1fa47febbbdfb694ed688ba61",
        "e6ec51a2ef933920ac1e6d3d8ba6ffac77fe94bfb79518b03cd9b94a14e97d3e",
        "fbecd00c62b01135f9e588883e80f2710a354c0eb73a33a2c5ab5602cc85f6ad",
        NULL //Append a null pointer to the list of targets to detect when we no longer have any more values to iterate over
    };
    char* salts[] = {
        "27fb57e9", "b7875b4b", "ec13ab35", "29b49fce", "acdabf8a",
        "64afe39d", "f0919683", "081b2451", "defb64a3", "017bb5b7", 
        NULL //Append a null pointer to the list of targets to detect when we no longer have any more values to iterate over
    };
    targetLength = 10;
    clock_t task3_start = clock();
    char** passwords3 = task3(targets3, salts);
    clock_t task3_stop = clock();
    double task3_elapsed = (double)(task3_stop - task3_start) * 1000.0 / CLOCKS_PER_SEC;
    print_passwords(passwords3);
    //If the amount of passwords added to the passwordStrings array equals the number of targets, we found all passwords!!
    if (nextPasswordIndex == targetLength) {
        printf("@@@ FOUND ALL TASK 3 PASSWORDS @@@\n");
    }
    printf("@@@ FINISHED TASK 3 IN %fms @@@\n", task3_elapsed);
    //Reset global variables
    cleanup();

    printf("############################\n");
    printf("############################\n");

    clock_t stop = clock();
    double elapsed = (double)(stop - start) * 1000.0 / CLOCKS_PER_SEC;
    printf("@@@ FINISHED ALL TASKS IN %fms @@@\n", elapsed);
}