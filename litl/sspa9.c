#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "sspa9.h"

#if COND_VAR
#include "interpose.h"
#include "utils.h"
#endif
#define LOCKED 1
#define UNLOCKED LOCKED-1
//---------file psquare_estimator.c--------------
void stampaStato(psqareEstimator * p){
	printf("Stato:\n");
	printf("quantile di ordine:%f \n",p->p);
	printf("altezza:\n");
	printf("%f   %f   %f   %f   %f\n",p->marker_heights[0],p->marker_heights[1],p->marker_heights[2],p->marker_heights[3],p->marker_heights[4]);
	printf("posizione:\n");
	printf("%f   %f   %f   %f   %f\n",p->marker_positions[0],p->marker_positions[1],p->marker_positions[2],p->marker_positions[3],p->marker_positions[4]);
	printf("posizione desiderata:\n");
	printf("%f   %f   %f   %f   %f\n",p->desidered_positions[0],p->desidered_positions[1],p->desidered_positions[2],p->desidered_positions[3],p->desidered_positions[4]);
	printf("incremento:\n");
	printf("%f   %f   %f   %f   %f\n",p->increments[0],p->increments[1],p->increments[2],p->increments[3],p->increments[4]);
	printf("flag %d\t c %d \n",p->initiated,p->c);

}

void initPsqaure(psqareEstimator * p,int q){
	p->p= ((float)(q/100.0));
	p->initiated=false;
	p->c=0;
	//init marker heights
	p->marker_heights[0]=0.0;
	p->marker_heights[1]=0.0;
	p->marker_heights[2]=0.0;
	p->marker_heights[3]=0.0;
	p->marker_heights[4]=0.0;
	//init marker position
	p->marker_positions[0]=1.0;
	p->marker_positions[1]=2.0;
	p->marker_positions[2]=3.0;
	p->marker_positions[3]=4.0;
	p->marker_positions[4]=5.0;
	//init desiderated position
	p->desidered_positions[0]=1.0;
	p->desidered_positions[1]=1.0 + 2.0*(p->p);
	p->desidered_positions[2]=1.0 + 4.0*(p->p);
	p->desidered_positions[3]=3.0 + 2.0*(p->p);
	p->desidered_positions[4]=5.0;
	//init increment
	p->increments[0]=0.0;
	p->increments[1]=(p->p)/2.0;
	p->increments[2]=p->p;
	p->increments[3]=(1.0+p->p)/2;
	p->increments[4]=1.0;
	AUDIT printf("Init struct\n");
	AUDIT stampaStato(p);
	return ;
}	

int find_cell(psqareEstimator * p,double newObservation){
    if(newObservation< p->marker_heights[0]){
    	return -1;
    }
    int i=0;
    while( (i+1 < 5) && (newObservation>=p->marker_heights[i+1]) ) i++;
    AUDIT printf("indice cella trovato: %d\n",i);
	return i;
}

double parabolic(psqareEstimator *p,int i, int d){

	double term1,term2,term3;

	term1 = d / (p->marker_positions[i + 1] - p->marker_positions[i - 1]);

    term2 = (p->marker_positions[i] - p->marker_positions[i - 1] + d) * (p->marker_heights[i + 1] - p->marker_heights[i]) / (p->marker_positions[i + 1] - p->marker_positions[i]);

    term3 = (p->marker_positions[i + 1] - p->marker_positions[i] - d) * (p->marker_heights[i] - p->marker_heights[i - 1]) / (p->marker_positions[i] - p->marker_positions[i - 1]);
    AUDIT printf("term1 %f\nterm2 %f\nterm3 %f\n",term1,term2,term3);
    return p->marker_heights[i] + term1 * (term2 + term3); 
}

double linear(psqareEstimator *p,int i,int d){
      return p->marker_heights[i] + d * (p->marker_heights[i + d] - p->marker_heights[i])/ (p->marker_positions[i+d] - p->marker_positions[i]);
}

void adjust_height_values(psqareEstimator *p){
    int i;
    float d;
    int d2;

    for(i=1;i<SIZE-1;i++){
    	d= p->desidered_positions[i] - p->marker_positions[i];
    	AUDIT printf("i %d d %f \n",i,d);
    	if( (d>=1.0 && (p->marker_positions[i+1]-p->marker_positions[i]>1)) || 
        (d<=-1.0 && (p->marker_positions[i-1] - p->marker_positions[i] ) < -1) ){
    		if(d<0){ d2=-1;}
    		else{ d2=1;}
    		double qprime;
    		qprime =parabolic(p,i,d2);
    		AUDIT printf("parabolic qprime: %f\n",qprime);
    		if(p->marker_heights[i-1] < qprime && qprime < p->marker_heights[i+1]){
    			p->marker_heights[i]=qprime;

    		}else{
    			qprime = linear(p,i,d2);
    			AUDIT printf("linear qprime: %f\n",qprime);
    			p->marker_heights[i]=qprime;
    		}

    		p->marker_positions[i] += d2;
    	}
    }
}

void update(psqareEstimator *p,long long new_observation){
	float app;
	int i,j,k;
	double newObservation;

	newObservation= (double) new_observation;
	AUDIT printf("\n\nvalore nuova osservazione: %f %lld \n",newObservation,new_observation);
	if(p->initiated==false){
		p->marker_heights[p->c]=newObservation;
		p->c=p->c+1;
		if(p->c==5){
			for(i=0;i<SIZE;i++){
				for(j=i;j<SIZE;j++){
					if(p->marker_heights[i]>p->marker_heights[j]){
						app=p->marker_heights[i];
						p->marker_heights[i]=p->marker_heights[j];
						p->marker_heights[j]=app;
					}
				}

			}
			p->initiated=true;
			AUDIT printf("\n\ndopo 5 elementi\n");
		}
		AUDIT stampaStato(p);
		return;
	}
	
    AUDIT printf("\nCerco la Cella\n");
    i=find_cell(p,newObservation);
    if(i==-1){
    	p->marker_heights[0] = newObservation;
    	k=0;
    }else{
	    if(i==4){
	    	p->marker_heights[4]= newObservation;
	    	k=3;
	    }else{
	    	k=i;
	    }
    }
    AUDIT stampaStato(p);
    
    AUDIT printf("\nAggiorno la posizione\n");
    for(j=k+1;j<SIZE;j++){
        	p->marker_positions[j]++;
    }
    AUDIT stampaStato(p);
    AUDIT printf("\nAggiorno la posizione desiderata\n");
    for(j=0;j<SIZE;j++){
    	p->desidered_positions[j]=p->desidered_positions[j]+p->increments[j];

    }
    AUDIT stampaStato(p);
    AUDIT printf("\nfaccio l'aggiustamento dell'altezza\n");
    adjust_height_values(p);
	AUDIT stampaStato(p);
	return;
}

long long p_estimate(psqareEstimator *p){
	if( p->c > 2){
	    return (long long)p->marker_heights[2];
	}
    return 50; //dovrei sostituirlo con qualcos'altro
}
//---------file sspa_profiling.c-----------

unsigned long long getCurrentTime(void){
    unsigned long long Uptime=0;
    unsigned long long LowTime=0;
    unsigned long long numCycle=0;
    __asm__ volatile (
    "rdtsc  \n"
    : "=a" (LowTime), "=d" (Uptime)
    :
    :  
    );
    numCycle = Uptime<<32 | LowTime;
    return numCycle;
}

 //------file kobloc.c-------

int __init_lock(my_diff time,int ratio){
    return syscall(__NR__INIT_LOCK__,time,ratio);
}
int __acquire_lock(int idLock,my_time last,my_diff m,int numCS){
    return syscall(__NR__ACQUIRE_LOCK__,idLock,last,m,numCS);
}
int __release_lock(int idLock,my_diff m,int numCS){
    return syscall(__NR__RELEASE_LOCK__,idLock,m,numCS); 
} 
int __destroy_lock(int idLock){
    return syscall(__NR__DESTROY_LOCK__,idLock);
}

int sspalock_init(sspa_lock* ret){
    if(ret==NULL)   return -1;
    ret->num_spin = 0;
    ret->numCS = 0;
    ret->state = 0;
    ret->last_cs_ts = 0;
    ret->ema_cs = DEFAULT_TIME;
    ret->numThreadTry=NUM_CPU;
    //ret->ema_err = 10;
    initPsqaure(&(ret->psquare),30);
    ret->idLock = __init_lock(DEFAULT_TIME,CSRATIO);
    //printf("ret->idLock:%lld\n",ret->idLock);
    ret->test=0;
    return ret->idLock;
}

void sspalock_init_context(lock_mutex_t *impl,
                          lock_context_t *context, int number) {
}

sspa_lock * sspalock_create(const pthread_mutexattr_t *attr){
    sspa_lock* impl=(sspa_lock*) malloc(sizeof(sspa_lock));
    int ret=sspalock_init(impl);
    if(ret<0){ 
	    free(impl);
	    return NULL;
	}
    #if COND_VAR
        REAL(pthread_mutex_init)(&impl->posix_lock, attr);  
    #endif
    return impl;
}   

int sspalock_lock(sspa_lock *lock,sspa_context_t *me){
    int gotoSleep,numCS;
    my_time start;
    volatile int my_ticket;
    my_diff timePassed=0;
    int res=0;
    if(lock==NULL) return -1;
    gotoSleep = 0;
sleep:
    if(gotoSleep){
        numCS = lock->numCS;
        __acquire_lock(lock->idLock,lock->last_cs_ts,lock->ema_cs,numCS);
    }
    my_ticket=__sync_fetch_and_add(&(lock->num_spin),1);
    start = getCurrentTime();
    do{
	//    long long time = p_estimate(&(lock->psquare));
        while(
			lock->state==LOCKED  && timePassed < p_estimate(&(lock->psquare))
		){
            timePassed=((my_diff)(getCurrentTime() - start))/HZToNano;
	    continue;
        }
        res = __sync_bool_compare_and_swap(&(lock->state),UNLOCKED,LOCKED);
        timePassed=((my_diff)(getCurrentTime() - start))/HZToNano;
        AUDIT printf("%d sono bloccato %d %lld\n",my_ticket,res,timePassed);
    }while( !( res == 1 || timePassed > p_estimate(&(lock->psquare)) ) );
    __sync_fetch_and_sub(&(lock->num_spin),1);    
    if(!res){
        gotoSleep = my_ticket >= lock->numThreadTry;
        AUDIT printf("%d %d %d %d\n",gotoSleep,my_ticket,numCS,lock->numThreadTry);
        goto sleep;
    } 
    lock->last_cs_ts=getCurrentTime();
    return 0;
}
void sspalock_unlock(sspa_lock *lock,sspa_context_t *me){ 
    int K,cond,numCS;
    my_diff new_sample = ((my_diff)(getCurrentTime() - lock->last_cs_ts))/HZToNano;
    lock->ema_cs = ALFA*(lock->ema_cs) + (1-ALFA)*new_sample;
    numCS=__sync_fetch_and_add(&(lock->numCS),1);
    if(numCS%100==1 || numCS%100==2 || numCS%100==3)
    	update(&(lock->psquare),new_sample);
    //se finisco presto e nessuno sta spinnando allora
    K = (lock->ema_cs/p_estimate(&(lock->psquare)));
    if(K>NUM_CPU-1){
        __atomic_store_n(&(lock->numThreadTry),NUM_CPU-1,__ATOMIC_SEQ_CST);
    }else{
        __atomic_store(&(lock->numThreadTry),&(K),__ATOMIC_SEQ_CST);
    }    
    cond= lock->num_spin==0;
    __sync_fetch_and_sub(&(lock->state),1);
    if(lock->ema_cs - new_sample >200 && cond){
	__release_lock(lock->idLock,lock->ema_cs,lock->numCS);
    }
    return;
}
int sspalock_destroy(sspa_lock *lock){
    if(lock==NULL)
        return -1;
    //printf("destroy is call\n");
    __destroy_lock(lock->idLock);
    free(lock);
    return 0;
}
int sspalock_try_lock(sspa_lock *lock,sspa_context_t *me){
    return __sync_bool_compare_and_swap(&(lock->state),UNLOCKED,LOCKED);
}

int sspalock_cond_init(sspa_cond_t *cond, const pthread_condattr_t *attr) {
#if COND_VAR
    return REAL(pthread_cond_init)(cond, attr);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int sspalock_cond_timedwait(sspa_cond_t *cond, sspa_lock *lock, sspa_context_t *me,
                       const struct timespec *ts) {
#if COND_VAR
    int res;

    sspalock_unlock(lock,me);

    if (ts)
        res = REAL(pthread_cond_timedwait)(cond, &lock->posix_lock, ts);
    else
        res = REAL(pthread_cond_wait)(cond, &lock->posix_lock);

    if (res != 0 && res != ETIMEDOUT) {
        fprintf(stderr, "Error on cond_{timed,}wait %d\n", res);
        assert(0);
    }

    int ret = 0;
    if ((ret = REAL(pthread_mutex_unlock)(&lock->posix_lock)) != 0) {
        fprintf(stderr, "Error on mutex_unlock %d\n", ret == EPERM);
        assert(0);
    }

    sspalock_lock(lock, me);
    return res;
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
    return 0;
}

int sspalock_cond_wait(sspa_cond_t *cond, sspa_lock *lock, sspa_context_t *me) {
    return sspalock_cond_timedwait(cond, lock, me, 0);
}

int sspalock_cond_signal(sspa_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_signal)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int sspalock_cond_broadcast(sspa_cond_t *cond) {
#if COND_VAR
    DEBUG("[%d] Broadcast cond=%p\n", cur_thread_id, cond);
    return REAL(pthread_cond_broadcast)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}

int sspalock_cond_destroy(sspa_cond_t *cond) {
#if COND_VAR
    return REAL(pthread_cond_destroy)(cond);
#else
    fprintf(stderr, "Error cond_var not supported.");
    assert(0);
#endif
}


//questo se mi serve fare qualcosa con lo start dei thread o delle applicazioni
void sspalock_thread_start(void) {
}

void sspalock_thread_exit(void) {
}

void sspalock_application_init(void) {
}

void sspalock_application_exit(void) {
}
