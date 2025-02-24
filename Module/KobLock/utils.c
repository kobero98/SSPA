#include "koblock.h"
//blocco di funzioni ausiliarie per la scrittura del registro CR3
//unsigned long cr0;
static inline void write_cr0_forced(unsigned long val){
    unsigned long __force_order;
    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}
static inline void protect_memory(void){
    write_cr0_forced(cr0);
}
static inline void unprotect_memory(void){
    write_cr0_forced(cr0 & ~X86_CR0_WP);
}