#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/cpufreq.h>
#include <generated/timeconst.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/smp.h>
#include <linux/preempt.h>
#include "koblock.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kobero");
MODULE_DESCRIPTION("Modulo per i KobLock");
MODULE_VERSION("0.1");
#define MODNAME "KobLock"


#define SIZE_VET 128
#define BITMASK 0x00FFFFFF
#define SHIFT_VET 24
dinamicVectorElement vettore[SIZE_VET];//variabile che mantiene il puntatore al vettore dinamico dei lock
unsigned int ratio;
unsigned long cr0,cr4; 
unsigned long * nisyscall;
spinlock_t lockVettore;
unsigned long valAlloc=0;
unsigned long valDealloc=0;
#define CPUTIMER 19

unsigned long long getTime(void){
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


enum hrtimer_restart timer_callback(struct hrtimer *timer)
{
    head_request * element;
    request *app; 
    element = (head_request *) container_of(timer, head_request, timer);
    if(element == NULL){
        return HRTIMER_NORESTART;
    }
    app=element->head; 
    if(app==NULL){
        /*qui sarebbe impossibile entrare eppure... */
        //printk("Timer: trovato un app == NULL o un count vuoto %d\n",element->count);
        return  HRTIMER_NORESTART;
    }   
    app->status=1;
    wake_up_process(app->task);
    return HRTIMER_NORESTART;
}

static void func_smt_timer(void * info){
    struct __smtInfo * smt_info = (struct __smtInfo*) info;
    hrtimer_start(smt_info->timer,smt_info->duration,HRTIMER_MODE_REL);
    return;
}

//declare syscall
//diff: tempo che il thread vede di attesa
//M: tempo medio che il thread vede stimato della systemCall 
__SYSCALL_DEFINEx(4,_koblock_acquire,int,idLock,unsigned long long, lCS, long long, media,int,numCS){

        request * r;
        unsigned long long now;
        long long diff;
        ktime_t timePassed;
        ktime_t timeSleep;
        ktime_t proactive_awake_time;
        ktime_t M;
        ktime_t remain;
	    int ret,flag;
	    struct __smtInfo * smt_info; 
        int i,j;
        head_request * element;
        DECLARE_WAIT_QUEUE_HEAD(the_queue);
	//i= idLock>>SHIFT_VET;
        //j= idLock & BITMASK;
        i=idLock/16384;
    	j=idLock%16384;	
	//printk("sys acquire avviata  %d->(%d,%d) \n",idLock,i,j);
        //TO-DO: inserire controllo parametri e sopratutto sanitizzazione
        if(idLock<0 || !vettore[i].isAlloc || vettore[i].vet[j].valid!=2){
            //if(idLock<0){
		//printk("%s: Errore sys aquire BitMask idLock %d\n",MODNAME,idLock);
            //	return 0;}
	    //if(!vettore[i].isAlloc){
		//printk("%s: Errore sys aquire BitMask idLock %d,is alloc %d\n",MODNAME,idLock,vettore[i].isAlloc);    		    return 0;}
	    //if(vettore[i].vet[j].valid!=2)
		 //printk("%s: Errore sys aquire BitMask idLock %d,is alloc %d valid %lld\n",MODNAME,idLock,vettore[i].isAlloc,vettore[i].vet[j].valid);	    
	    return 0;
        }
        element=&(vettore[i].vet[j]);
        M=ns_to_ktime(media);
        //ma cosa succede se io non sono l'unico e rientro perche già c'é un altro in spin?
        // vuoldire che io non sarei entrato in query ma sono entrato quindi non serve!
        smt_info = (struct __smtInfo *) kmalloc(sizeof(struct __smtInfo ),GFP_KERNEL);
        r = (request *) kmalloc(sizeof(request),GFP_ATOMIC);
        if(r==NULL) return -1;
        r->task=current;
        r->next=NULL;
        r->prev=NULL;
        r->status=0;
        //Inserimento nella coda 
        //credo che da questa azione deve diventare tutto come unica azione atomica
        //overo far diventare questo thread unprintable
        //prendo il lock tramite strategia TTAS
        spin_lock(&(element->lock));
        if(lCS > element->last_start_cs_ts)
            element->last_start_cs_ts=lCS;
        if(numCS > element->num_cs){
            element->num_cs=numCS;
            element->expected_cs_duration=M;
	}   
        if(element->count==0){
            //la coda é vuota quindi io sono il primo che deve mettere il timer iniziale
            //printk("head\n");
	    now=getTime();
            diff = (long long) (((now - element->last_start_cs_ts)*10)/(ratio));
         
            timePassed=ns_to_ktime(diff);
            if(ktime_compare((element->expected_cs_duration*element->ratio)/100,ns_to_ktime(NS_MIN_PROACTIVE_AWAKE))<0){
                //printk("exit1\n");
		spin_unlock(&(element->lock));
                kfree(r);
                return 1;
            }
            
            proactive_awake_time=ktime_sub((element->expected_cs_duration*element->ratio)/100,ns_to_ktime(NS_MIN_PROACTIVE_AWAKE));
            
            if(ktime_compare(proactive_awake_time,timePassed)<0){
                //printk("exit2\n");   
		spin_unlock(&(element->lock));
                kfree(r);
                return 1;
            }
            timeSleep=ktime_sub(proactive_awake_time,timePassed);
            
            if(ktime_compare(timeSleep,element->threshold)<0){
                //printk("exit3\n");
		spin_unlock(&(element->lock));
                kfree(r);
                return 1;
            }
            element->head=r;
            element->tail=r; 
            smt_info->duration=timeSleep;
            smt_info->timer=&(element->timer);
            smp_call_function_single(CPUTIMER,func_smt_timer,smt_info,1);
        }else{
            //mi inserisco in coda
            element->tail->next=r;
            r->prev=element->tail;
            element->tail=r;    
        }
        element->count++; 
        //finisco la sezione critica
        spin_unlock(&(element->lock));   
        
        wait_event_interruptible(the_queue,r->status==1);//ma se mi sono svegliato per un segnale o per qualche altro motivo mi interessa?
        spin_lock(&(element->lock));
	    remain = hrtimer_get_remaining(&(element->timer));
            ret=hrtimer_cancel(&(element->timer));
            flag= r->status==1;
	    //qui il timer è sicuro sia finito
            //io sono l'unico in kernel CS CHE PUÒ MODIFICARE LA STRUTTURA
            element->count--;
	    if(r->status==2){
	    	return 1;
	    }
	    if(element->head==r) element->head=r->next; 
            if(element->tail==r) element->tail=r->prev;
            if(r->prev != NULL ) (r->prev)->next=r->next;                         
            if(r->next != NULL ) (r->next)->prev=r->prev;
 
            if(ret==0 && flag==0 ){
               //ci sta qualcuno che è stato svegliato il timer ne ha scelto quacluno che non sono io ma io sono passato prima nel prendere il lock e ho fermato il timer
               //posso lasciare la gestione del timer a qualcunaltro
                spin_unlock(&(element->lock));
                kfree(r);
                kfree(smt_info);
                return 0;        
            }
            if(flag==1){
                //io sono stato svegliato correttamente devo mettere io il timer per quello dopo
                //sarebbe da verificare se head ero io? 
                if(element->count>0){
                    //hrtimer_start(&(vettore[idLock].timer),vettore[idLock].expected_cs_duration,HRTIMER_MODE_REL);
                    // int this_cpu=get_cpu();
                    // int cpu=(this_cpu+1)%NR_CPUS;
                    smt_info->duration=element->expected_cs_duration;
                    smt_info->timer=&(element->timer);
                    smp_call_function_single(CPUTIMER,func_smt_timer,smt_info,1);  
                    kfree(smt_info);
                }
            }  
            if(ret==1 && flag==0){
                //sono stato svegliato da un segnale ed ho fermato il timer mi tolgo dalla coda 
                //e lascio percorrere per il tempo che mancava
                if(element->count>0){
                    //hrtimer_start(&(vettore[idLock].timer),remain,HRTIMER_MODE_REL);
                    //int this_cpu=();
                    //printk("%d %d\n",this_cpu,this_cpu+1%NR_CPUS);
                    //int cpu=(this_cpu+1)%NR_CPUS;
                    //trace_printk("%s: flag=0 and ret=1 CPU = %d\n",MODNAME,smp_processor_id());
                    smt_info->duration=remain;
                    smt_info->timer=&(element->timer);
                    smp_call_function_single(CPUTIMER,func_smt_timer,smt_info,1);
                    kfree(smt_info);
                }
            }

    spin_unlock(&(element->lock));
    kfree(r);
    return 1;
}
__SYSCALL_DEFINEx(3,_koblock_release,int,idLock,long long,M,int,numCS){
        int ret,i,j;
        ktime_t remain;
        head_request * element;
	//printk("call release\n");
        //i= idLock>>SHIFT_VET;
        //j= idLock & BITMASK;
        i=idLock/16384;
    	j=idLock%16384;
	__sync_fetch_and_add(&valDealloc,1);
	//potrei svegliare e segnalare il problema       
        if(idLock<0 || !vettore[i].isAlloc || vettore[i].vet[j].valid!=2){
        	 
             //printk("%s: Errore sys release BitMask idLock %d->(%d,%d),is alloc %d valid %lld\n",MODNAME,idLock,i,j,vettore[i].isAlloc,vettore[i].vet[j].valid);
	     return 0;
        }   
        element=&(vettore[i].vet[j]);
        spin_lock(&(element->lock));
        remain = hrtimer_get_remaining(&(element->timer));
        ret=hrtimer_cancel(&(element->timer));
        if(ret > 0){  
	      	timer_callback(&(element->timer));
        }
        //forse l'ottimo sarebbe attivare il timer ma potrei rallentare troppo il thread corrente 
        //questa dovrebbe essere una buona ottimizzazione
        __atomic_store_n(&(element->num_cs),numCS,__ATOMIC_SEQ_CST);
        __atomic_store_n(&(element->expected_cs_duration),ns_to_ktime(M),__ATOMIC_SEQ_CST);
        spin_unlock(&(element->lock));
        return 0;
}
//syscall per inizializzare un lock
__SYSCALL_DEFINEx(2,_koblock_init,long long,time,int,ratio){
    int myticket,ticket,i,j,k,flag;
    head_request * element; 	
    flag=0;
    spin_lock(&lockVettore);
    valAlloc++;
    ticket=-1;
    for(i=0;i<SIZE_VET;i++){
        if(vettore[i].free!=0){
            ticket=i;
            break;
        }
    }
    if(ticket == -1){
	ticket = valAlloc;
        spin_unlock(&lockVettore);
        printk("ticket -1 tutte le entri occupate %d\n",ticket);
	return -1;
    }
    i=ticket;
    if(!vettore[i].isAlloc){
        //alloca
	//printk("Alloco memoria vettore i:%d\n",i);
        if(vettore[i].vet== NULL){
	//if(sizeof(head_request)*vettore[i].dim<KMALLOC_MAX_SIZE){
              //printk("alloco memoria con kmalloc\n");
	      vettore[i].vet = (head_request *) kmalloc(sizeof(head_request)*vettore[i].dim,GFP_KERNEL|__GFP_ZERO); //to sotto lock se non dormo è meglio
       	     // printk("vet[%d]: %x\n",i,vettore[i].vet);
       	}
       // else{
	    //printk("alloc memoria con vmalloc\n teoricamente se vado qui ci sono problemi\n");
            //teoricamente qui non devo mai andarci
         //   vettore[i].vet = (head_request *) vmalloc(sizeof(head_request)*vettore[i].dim);
       // }
        if(vettore[i].vet==NULL){
            spin_unlock(&lockVettore);
            printk("io esco di qua non riesco ad allocare \n");
            return -1;
        }
        vettore[i].free = vettore[i].dim;
        vettore[i].isAlloc=1;
	flag=1;
    }
    j=-1;
    for(k=0;k<vettore[i].dim;k++){
        if(vettore[i].vet[k].valid == 0){
            __atomic_store_n(&(vettore[i].vet[k].valid),1,__ATOMIC_SEQ_CST);
	    j=k;
	    //printk("trovo almeno un' elemento\n");
            element=&(vettore[i].vet[k]);
            break;
        }
    }
    if(j==-1){
    	printk("%s: Errore critico\n",MODNAME);
	if(flag==1){
		kfree(vettore[i].vet);
		vettore[i].isAlloc=0;
	}
	spin_unlock(&lockVettore);
	return -1;
    }
    vettore[i].free--;
    spin_unlock(&lockVettore);
    myticket=(i<<SHIFT_VET)+j;
    //sistemo la request
    spin_lock_init(&(element->lock));
    //printk("non è il lock\n");
    element->count=0;
    element->num_cs=1;
    element->head=NULL;
    element->tail=NULL;
    element->threshold=ns_to_ktime(NS_MIN_PROACTIVE_AWAKE);
    element->last_start_cs_ts=getTime();
    //printk("inizio a settare il timer\n");
    hrtimer_init(&(element->timer),CLOCK_MONOTONIC,HRTIMER_MODE_REL);
    //printk("non è il timer \n");
    element->timer.function = &timer_callback;
    element->expected_cs_duration = ns_to_ktime(time);
    element->ratio=ratio;
    __atomic_store_n(&(element->valid),2,__ATOMIC_SEQ_CST);
    //printk("fino a qui ci arrivo?\n"); 
    return myticket;
}
void statistics(int i){
	//int i;
	//for(i=0;i<SIZE_VET;i++){
	printk("vettore[%d].dim=%d\n",i,vettore[i].dim);
	printk("vettore[%d].free=%d\n",i,vettore[i].free);
	printk("vettore[%d].isAlloc=%d\n",i,vettore[i].isAlloc);
	printk("vettore[%d].vett=%p\n",i,vettore[i].vet);
	//}
}	

__SYSCALL_DEFINEx(1,_koblock_destroy,int,idLock){
    //è da migliorare...  ASSOLUTAMENTE!!!
    request *q,*p;
    head_request *element;
    int i,j;
    //printk("call destroy\n");
    //i=idLock>>SHIFT_VET;
    //j=idLock& BITMASK;
    i=idLock/16384;
    j=idLock%16384;
    //spin_lock(&lockVettore);
    //__sync_fetch_and_add(&valDealloc,1); 
    //printk("call destroy %d->(%d,%d)\n",idLock,i,j);
    element=&(vettore[i].vet[j]);
    __atomic_store_n(&(element->valid),2,__ATOMIC_SEQ_CST);
    spin_lock(&(element->lock));
    hrtimer_cancel(&(element->timer));
    q=element->head; //cosa che non mi convince qua !! se questi li dealloco nessuno si sveglia...
    while(q!=NULL){
            p=q;
            q=q->next;
	    __atomic_store_n(&(p->status),2,__ATOMIC_SEQ_CST);
            wake_up_process(p->task);
	    //kfree(p);
    }
    element->head=NULL;
    element->tail=NULL;
    //vettore[i].vet[j].count=0;
    //vettore[i].vet[j].num_cs=1;
    //vettore[i].vet[j].head=NULL;
    //vettore[i].vet[j].tail=NULL;
    //vettore[i].vet[j].threshold=ns_to_ktime(NS_MIN_PROACTIVE_AWAKE);
    //vettore[i].vet[j].last_start_cs_ts=getTime();
    //printk("inizio a settare il timer\n");
    //hrtimer_init(&(vettore[i].vet[j].timer),CLOCK_MONOTONIC,HRTIMER_MODE_REL);
		    //printk("non è il timer \n");
    //vettore[i].vet[j].timer.function = &timer_callback;
    //vettore[i].vet[j].expected_cs_duration = ns_to_ktime(400);
    //vettore[i].vet[j].ratio=90;
    
    //__atomic_store_n(&(vettore[i].vet[j].valid),2,__ATOMIC_SEQ_CST);
    spin_unlock(&(element->lock));
    //printk("inizio qui con questo count %d\n",element->count);
    //while(element->count!=0) continue;
    //printk("%s: destroy lock number  %d\n",MODNAME,idLock);
    //vettore[i].free++;
    //if(i!=0 && vettore[i].free == vettore[i].dim){
        //printk("dealloco il vettore count->%d i,j:%d,%d\n",element->count,i,j);
	//kfree(vettore[i].vet); //dealloco la memoria se serve 
        //vettore[i].isAlloc=0;
    	//statistics(i);
    //}
    //spin_unlock(&lockVettore);
    return 0; 
}



static unsigned long sys_koblock_destroy = (unsigned long) __x64_sys_koblock_destroy;	
static unsigned long sys_koblock_init = (unsigned long) __x64_sys_koblock_init;	
static unsigned long sys_koblock_release = (unsigned long) __x64_sys_koblock_release;	
static unsigned long sys_koblock_acquire = (unsigned long) __x64_sys_koblock_acquire;	


//Parametri di Input del modulo
//1. Posizione della Systemcall table
//2. Array di indici delle entry libere
unsigned long systemcall_table=0x0;
module_param(systemcall_table,ulong,0660);
int free_entries[15];
module_param_array(free_entries,int,NULL,0664);
module_param(ratio,int,0664);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0) 
#define INST_LEN 5
char jump_inst[INST_LEN];
unsigned char original_inst[INST_LEN]; // Buffer to store the original instruction
unsigned long x64_sys_call_addr;
int offset;
static struct kprobe kp_x64_sys_call = { .symbol_name = "x64_sys_call" };

//stuff here is using retpoline
static inline void call(struct pt_regs *regs, unsigned int nr){
    	asm volatile("mov (%1, %0, 8), %%rax\n\t"
             "jmp __x86_indirect_thunk_rax\n\t"
             :
             : "r"((long)nr), "r"(systemcall_table)
             : "rax");
}

#endif

//funzioni di inizializzazione del modulo
int init_func(void){
    //inserimento Systemcall
    unsigned long ** sys_call_table;
    unsigned int val1,val2;
    int i,j;
    if(systemcall_table!=0){
        //prendo il ratio di CPU per utilizzarlo al fine di stimare il tempo
        val1=0;
        val2=0;
        native_rdmsr(MSR_PLATFORM_INFO, val1, val2);
        ratio = (val1>>8)& 0x000000FF;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        if (register_kprobe(&kp_x64_sys_call)) {
                    printk(KERN_ERR "%s: cannot register kprobe for x64_sys_call\n", MODNAME);
                    return -1;
            }

            x64_sys_call_addr = (unsigned long)kp_x64_sys_call.addr;
            unregister_kprobe(&kp_x64_sys_call);

            /* JMP opcode */
            jump_inst[0] = 0xE9;
            memcpy(original_inst, (unsigned char *)x64_sys_call_addr, INST_LEN);
            /* RIP points to the next instruction. Current instruction has length 5 */
            offset = (unsigned long)call - x64_sys_call_addr - INST_LEN;
            memcpy(jump_inst + 1, &offset, sizeof(int)); //????
    #endif

        //inizio a scrivere  le entry delle systemcall che mi servono
        cr0 = read_cr0();
        cr4 = native_read_cr4();   
        begin_syscall_table_hack(cr0,cr4);    
        sys_call_table = (void*) systemcall_table; 
        nisyscall = sys_call_table[free_entries[0]];
        sys_call_table[free_entries[0]] = (unsigned long *) sys_koblock_init;
        sys_call_table[free_entries[1]] = (unsigned long *) sys_koblock_acquire;
        sys_call_table[free_entries[2]] = (unsigned long *) sys_koblock_release;
        sys_call_table[free_entries[3]] = (unsigned long *) sys_koblock_destroy;
        
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        //these kernel versions are configured to avoid the usage of the syscall table 
        //this piece of code intercepts the activation of the syscall dispatcher and
        //redirects control to the function that restores the usage of the syscall table 
        //it may be possible that I did not check all the kernel cofigurations
        //the user can add here whichever configuration he wants that avoids the
        //usage of the syscall table while dispatching syscalls
                memcpy((unsigned char *)x64_sys_call_addr, jump_inst, INST_LEN);
        #endif
        
        end_syscall_table_hack(cr0,cr4);
        //ffffffffa4a002e0
        //sys_ni_syscall found at ffffffffa3407a90
        printk("%s: koblock_init: %d\n",MODNAME,free_entries[0]);
        printk("%s: koblock_acquire: %d\n",MODNAME,free_entries[1]);
        printk("%s: koblock_releas: %d\n",MODNAME,free_entries[2]);
        printk("%s: koblock_destroy: %d\n",MODNAME,free_entries[3]);
        printk("%s: allocazione primo vettore dinamico\n",MODNAME);
	
	for(i=0;i<SIZE_VET;i++){
		vettore[i].vet=(head_request *) kmalloc(sizeof(head_request)*16384,__GFP_ZERO|GFP_KERNEL);	
		if(vettore[i].vet == NULL){
		    printk("%s-Errore: allocazione fallita\n",MODNAME);
		    begin_syscall_table_hack(cr0,cr4);    
		    sys_call_table[free_entries[0]] = nisyscall;
		    sys_call_table[free_entries[1]] = nisyscall;
		    sys_call_table[free_entries[2]] = nisyscall;
		    sys_call_table[free_entries[3]] = nisyscall;
		    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
		    memcpy((unsigned char *)x64_sys_call_addr, original_inst, INST_LEN);
		    #endif
		    end_syscall_table_hack(cr0,cr4);
		    return -1;
		}
		vettore[i].isAlloc=1;
		vettore[i].dim=16384;
		vettore[i].free=16384;
		for(j=0;j<vettore[i].dim;j++){ 
		    vettore[i].vet[j].count=0;
		    vettore[i].vet[j].num_cs=1;
		    vettore[i].vet[j].head=NULL;
		    vettore[i].vet[j].tail=NULL;
		    vettore[i].vet[j].threshold=ns_to_ktime(NS_MIN_PROACTIVE_AWAKE);
		    vettore[i].vet[j].last_start_cs_ts=getTime();
		    //printk("inizio a settare il timer\n");
		    hrtimer_init(&(vettore[i].vet[j].timer),CLOCK_MONOTONIC,HRTIMER_MODE_REL);
		    //printk("non è il timer \n");
		    vettore[i].vet[j].timer.function = &timer_callback;
		    vettore[i].vet[j].expected_cs_duration = ns_to_ktime(400);
		    vettore[i].vet[j].ratio=90;
		    spin_lock_init(&(vettore[i].vet[j].lock));
		    __atomic_store_n(&(vettore[i].vet[j].valid),0,__ATOMIC_SEQ_CST);
		}
	}
	/*
       	vettore[0].vet = (head_request *) kmalloc(sizeof(head_request)*1024,__GFP_ZERO|GFP_KERNEL);
	if(vettore[0].vet == NULL){
            printk("%s-Errore: allocazione fallita\n",MODNAME);
            begin_syscall_table_hack(cr0,cr4);    
            sys_call_table[free_entries[0]] = nisyscall;
            sys_call_table[free_entries[1]] = nisyscall;
            sys_call_table[free_entries[2]] = nisyscall;
            sys_call_table[free_entries[3]] = nisyscall;
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
            memcpy((unsigned char *)x64_sys_call_addr, original_inst, INST_LEN);
            #endif
            end_syscall_table_hack(cr0,cr4);
            return -1;
        }
        vettore[0].isAlloc=1;
        vettore[0].dim=1024;
        vettore[0].free=1024;
        printk("%s: sistemazione primo vettore\n",MODNAME);
        for(i=1;i<SIZE_VET;i++){
            vettore[i].isAlloc=0;
            vettore[i].vet=NULL;
            if((1024<<i)*sizeof(head_request)<KMALLOC_MAX_SIZE && i<21){    
                vettore[i].free=1024<<i;
                vettore[i].dim=1024<<i;
            }else{
                vettore[i].free=vettore[i-1].free;
                vettore[i].dim=vettore[i-1].dim;
            }
            printk("dimensione impostata per l'elemento i:%d a dim %d free %d\n",i,vettore[i].dim,vettore[i].free);
        }
        printk("%s: inizializzazione spinlock\n",MODNAME);
	*/
        spin_lock_init(&lockVettore);
    }else{
        printk("%s-Errore: systemcall Table non trovata\n",MODNAME);
        return -1;
    }
    printk("%s: modulo inserito con successo\n",MODNAME);
    printk("%s: size of head_request:%ld %ld\n",MODNAME,KMALLOC_MAX_SIZE,sizeof(head_request));
    return 0;
}

void cleanup_func(void){
    unsigned long ** sys_call_table;
    int i,j;
    printk("%s: eliminazione del Modulo\n",MODNAME);
    printk("%s: ho visto tot alloc %ld e tot dealloc %ld\n",MODNAME,valAlloc,valDealloc);
    
    cr0 = read_cr0();
    cr4 = native_read_cr4();   
    
    begin_syscall_table_hack(cr0,cr4);
    sys_call_table = (void*) systemcall_table; 
    printk("entry num: %d %d %d \n",free_entries[0],free_entries[1],free_entries[2]);
    sys_call_table[free_entries[0]] = nisyscall;
    sys_call_table[free_entries[1]] = nisyscall;
    sys_call_table[free_entries[2]] = nisyscall;
    sys_call_table[free_entries[3]] = nisyscall;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
    //se ho modificato rimetto l'istruzione precedente la modifica
    memcpy((unsigned char *)x64_sys_call_addr, original_inst, INST_LEN);
    #endif
    end_syscall_table_hack(cr0,cr4);
    for(i=0;i<SIZE_VET;i++) {
        if(vettore[i].vet != NULL){
            for(j=0;j<vettore[i].dim;j++)
                if(vettore[i].vet[j].valid==2)
                    //sarebbe da controllare anche che head e tail non stiano puntando a dati da cancellare
                    hrtimer_cancel(&(vettore[i].vet[j].timer));
            kfree(vettore[i].vet);
        }
    }
    printk("%s: modulo smontato con successo\n",MODNAME);
    return;
}

module_init(init_func);
module_exit(cleanup_func);
