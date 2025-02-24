#ifndef __SSPA_H__
#define __SSPA_H__

#define MEDIAEXP 1
#define my_time unsigned long long
#define my_diff long long
#ifndef ALFA
#define ALFA 0.98
#endif
#define NUM_CPU 19
#define HZToNano 2.2

#if COND_VAR
#include "padding.h"
#include <errno.h>
#endif
#define LOCK_ALGORITHM "SSPA"
#define NEED_CONTEXT 0
#define SUPPORT_WAITING 0
#define NO_INDIRECTION 0


#ifndef __NR__INIT_LOCK__
#define __NR__INIT_LOCK__ 134
#endif

#ifndef __NR__ACQUIRE_LOCK__
#define __NR__ACQUIRE_LOCK__ 174
#endif

#ifndef __NR__RELEASE_LOCK__
#define __NR__RELEASE_LOCK__ 177
#endif

#ifndef __NR__DESTROY_LOCK__
#define __NR__DESTROY_LOCK__ 178
#endif

#ifndef SPIN_PHASE_DURATION
#define SPIN_PHASE_DURATION 5
#endif

#ifndef NUM_THREAD_INIZIAL_TRY
#define NUM_THREAD_INIZIAL_TRY 3
#endif

#ifndef DEFAULT_TIME
#define DEFAULT_TIME 400
#endif

#ifndef L_CACHE_LINE_SIZE
#define L_CACHE_LINE_SIZE 128
#endif

#ifndef CSRATIO
#define CSRATIO 90
#endif
//almomento  non lo considero, rappresenta il costo di andare ad invocare una syscall
//epsilon deve essere circa il tempo di passaggio per la system call
#include <stdbool.h>

#define AUDIT if(0)

#define SIZE 5

typedef struct psqare{
	float p;
	double marker_heights[SIZE];
	double marker_positions[SIZE];
	double desidered_positions[SIZE];
	double increments[SIZE];
	bool initiated;
	int c;
}psqareEstimator;


typedef struct __sspa_lock{
    #if COND_VAR
        pthread_mutex_t posix_lock;
        char __pad[pad_to_cache_line(sizeof(pthread_mutex_t))];
    #endif
    volatile int state __attribute__((aligned(L_CACHE_LINE_SIZE)));
    volatile int numCS __attribute__((aligned(L_CACHE_LINE_SIZE)));
    volatile int num_spin;
    volatile int test;
    my_time last_cs_ts;
    my_diff ema_cs;
    psqareEstimator psquare;
    int numThreadTry;
    int idLock;
}sspa_lock __attribute__((aligned(L_CACHE_LINE_SIZE)));;

typedef void    *sspa_context_t;
typedef sspa_lock lock_mutex_t;
typedef pthread_cond_t sspa_cond_t;
typedef void    *lock_context_t; // Unused, take the less space as possible

int sspalock_init(sspa_lock*);
sspa_lock* sspalock_create(const pthread_mutexattr_t *);
int sspalock_lock(sspa_lock *,sspa_context_t *);
int sspalock_try_lock(sspa_lock *,sspa_context_t *);
void sspalock_unlock(sspa_lock *,sspa_context_t *);
int sspalock_destroy(sspa_lock *);

int sspalock_cond_init(sspa_cond_t *, const pthread_condattr_t *);
int sspalock_cond_timedwait(sspa_cond_t *cond, sspa_lock *lock,sspa_context_t *me, const struct timespec *ts);
int sspalock_cond_wait(sspa_cond_t *cond, sspa_lock *lock,sspa_context_t *me);
int sspalock_cond_signal(sspa_cond_t *cond);
int sspalock_cond_broadcast(sspa_cond_t *cond);
int sspalock_cond_destroy(sspa_cond_t *cond);

void sspalock_thread_start(void);
void sspalock_thread_exit(void);
void sspalock_application_init(void);
void sspalock_application_exit(void);

typedef sspa_lock lock_mutex_t;
typedef sspa_cond_t lock_cond_t;
typedef void    *lock_context_t; // Unused, take the less space as possible

#define lock_mutex_create sspalock_create
#define lock_mutex_lock sspalock_lock
#define lock_mutex_trylock sspalock_try_lock
#define lock_mutex_unlock sspalock_unlock
#define lock_mutex_destroy sspalock_destroy

#define lock_cond_init sspalock_cond_init
#define lock_cond_timedwait sspalock_cond_timedwait
#define lock_cond_wait sspalock_cond_wait
#define lock_cond_signal sspalock_cond_signal
#define lock_cond_broadcast sspalock_cond_broadcast
#define lock_cond_destroy sspalock_cond_destroy

#define lock_thread_start sspalock_thread_start
#define lock_thread_exit sspalock_thread_exit
#define lock_application_init sspalock_application_init
#define lock_application_exit sspalock_application_exit

#define lock_init_context sspalock_init_context

#endif
