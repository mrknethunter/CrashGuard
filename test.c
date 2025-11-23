#include<stdio.h>

int main(void) {
    int *p = NULL;


    *p = 10; // simulate a segfault
}