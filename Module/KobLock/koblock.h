#include <linux/hrtimer.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

#define MAX_NLOCK 8192
#define DIMENSIONE_ELEMENTO_BITMASK (sizeof(uint64_t)*8)
#define BITMASKSIZE (MAX_NLOCK/DIMENSIONE_ELEMENTO_BITMASK + 1*((MAX_NLOCK % DIMENSIONE_ELEMENTO_BITMASK)!=0))
#define NS_TO_RESTART 100
#define NS_MIN_PROACTIVE_AWAKE 150


#define CPU_PAUSE() asm volatile("pause\n" : : : "memory")

typedef struct  __attribute__((__packed__)) __request{
    volatile uint64_t status;
    struct task_struct *task;
    struct __request * next;
    struct __request * prev;
}request;

typedef struct head_request{
    spinlock_t lock;
    //volatile uint64_t lock; //sarebbe da allineare alla memoria 
    volatile uint64_t valid; //questa ci penso bene
    struct __request * head;
    struct __request * tail;
    struct hrtimer timer; //timer
    ktime_t expected_cs_duration;
    unsigned long long last_start_cs_ts; //ultima sezione critica che è stata vita 
    volatile ktime_t threshold;
    int count;
    int ratio;
    int num_cs;
}head_request;


typedef struct dinamicVectorElement{
    int dim;
    int free;
    int isAlloc;
    head_request * vet;
}dinamicVectorElement;
struct __smtInfo {
    struct hrtimer* timer;
    ktime_t duration;
};
//funzioni di gestione della bitmask
extern int trovaBit(void);
extern int checkBit(int);
extern void setBitDown(int);
extern void setBitUP(int);
extern void initBitmask(void);
//funzioni per la scrittura del registro di CR3
//blocco di funzioni ausiliarie
//devo trasferirle in un nuovo file
// extern static inline void write_cr0_forced(unsigned long);
// extern static inline void protect_memory(void);
// extern static inline void unprotect_memory(void);
static inline void write_cr0_forced(unsigned long val){
    unsigned long __force_order;
    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}
static inline void protect_memory(unsigned long cr0){
    write_cr0_forced(cr0);
}
static inline void unprotect_memory(unsigned long cr0){
    write_cr0_forced(cr0 & ~X86_CR0_WP);
}
static inline void write_cr4_forced(unsigned long val){
        unsigned long __force_order;
        asm volatile("mov %0, %%cr4" : "+r"(val), "+m"(__force_order));
}
static inline void conditional_cet_disable(unsigned long cr4){
#ifdef X86_CR4_CET
        if (cr4 & X86_CR4_CET)
                write_cr4_forced(cr4 & ~X86_CR4_CET);
#endif
}

static inline void conditional_cet_enable(unsigned long cr4){
#ifdef X86_CR4_CET
        if (cr4 & X86_CR4_CET)
                write_cr4_forced(cr4);
#endif
}

static inline void begin_syscall_table_hack(unsigned long cr0,unsigned long cr4){
        preempt_disable();
        conditional_cet_disable(cr4);
        unprotect_memory(cr0);
}

static inline void end_syscall_table_hack(unsigned long cr0,unsigned long cr4){
        protect_memory(cr0);
        conditional_cet_enable(cr4);
        preempt_enable();
}
