#include <linux/kernel.h>
#include "koblock.h"


uint64_t bitmask[BITMASKSIZE];
//funzione di check
void stampa(void){
    int i;
    printk("BITMASK\n");
    for(i=0;i<BITMASKSIZE;i++){
        printk("%lld\n",bitmask[i]);
    }
    printk("\n");
}

//possono diventare macro
void setBitUP(int index){
    int i= index/DIMENSIONE_ELEMENTO_BITMASK;
    uint64_t x = 1 << (index%DIMENSIONE_ELEMENTO_BITMASK);
    __sync_fetch_and_or(&(bitmask[i]),x); 
    //stampa();   
}
//imposta un bit a 0 della bit mask corrispondente
void setBitDown(int index){
    int i= index/DIMENSIONE_ELEMENTO_BITMASK;
    uint64_t x = ~(1 << (index%DIMENSIONE_ELEMENTO_BITMASK));
    __sync_fetch_and_and(&(bitmask[i]),x);
    //stampa();
}
//verifica il valore del bit del blocco
//torna 1 se nella bitmask il bit index é 1
//torna 0 se nella bitmask il bit index é 0 
int checkBit(int index){
    int i;
    uint64_t pos;
    i=index/DIMENSIONE_ELEMENTO_BITMASK;
    pos = 1 << (index%DIMENSIONE_ELEMENTO_BITMASK);
    return (bitmask[i] & pos) == pos;
}
//trova un blocco con bit pari a 0
int trovaBit(void){
    int i,index;
    index=-1;
    for(i=0;i<MAX_NLOCK;i++){
        if(!checkBit(i)){
            index=i;
            break;
        }
    }
    return index;
}
void initBitmask(void){
   int i; 
   for(i=0;i<BITMASKSIZE;i++) bitmask[i]=0;
}
