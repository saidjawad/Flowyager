#ifndef FT_QUEUE_H
#define FT_QUEUE_H 1
#ifdef __cplusplus
extern "C" {
#endif
#include <pthread.h>
#include<arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#define QUEUESIZE 80000

typedef struct {
    uint64_t priority;
    void * data;
} node_pq;

typedef struct {
    node_pq *nodes;
    int len;
    int size;
} heap_t;

typedef struct {
  void **buf;
  long size; 
  long head, tail;
  int full, empty;
  pthread_mutex_t *mut;
  pthread_cond_t *not_full, *not_empty;
} ft_queue;

typedef struct {
    void **buf;
     long size;
    long head;
    int full, empty;
    pthread_mutex_t *mut;
    pthread_cond_t *not_full, *not_empty;
} ft_stack;


inline ft_stack * stack_new(long size){
  ft_stack * s ; 
  s = (ft_stack *)calloc (1,sizeof (ft_stack));
  if (s == NULL) return (NULL);
  void **buff = (void **)calloc(size, sizeof(void *));
  s->buf = buff; 
  s->size = size;
  s->empty = 1;
  s->full = 0;
  s->head = -1;
  s->mut = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t));
  pthread_mutex_init (s->mut, NULL);
  s->not_full = (pthread_cond_t *) malloc (sizeof (pthread_cond_t));
  pthread_cond_init (s->not_full, NULL);
  s->not_empty = (pthread_cond_t *) malloc (sizeof (pthread_cond_t));
  pthread_cond_init (s->not_empty, NULL);  
  return (s);
}
inline void stack_destroy (ft_stack *s)
{
  pthread_mutex_destroy (s->mut);
  free (s->mut);
  pthread_cond_destroy (s->not_full);
  free (s->not_full);
  pthread_cond_destroy (s->not_empty);
  free (s->not_empty);
  free(s->buf);
  free (s);
}
inline void stack_push (ft_stack *s, void *in)
{
  if (s->full) {
    fprintf(stderr, "trying to push into a full stack");
    exit(-1); 
  }
  s->head = s->head + 1; 
  s->buf[s->head] = in;
  if(s->head == s->size-1){
    s->full = 1;
  }
  s->empty = 0;
  return;
}
inline void stack_pop (ft_stack *s, void **out)
{
  if (s->empty){
    fprintf(stderr, "trying to pop an empty stack"); 
    exit(-1);
  }

  *out = s->buf[s->head];
  s->head = s->head - 1;
  
  if(s->head < 0) s->empty = 1;
  
  s->full = 0;  
  return;
}
inline void stack_peek(ft_stack *s, void **out)
{
  *out = s->buf[s->head - 1];

}

inline ft_queue *queue_new (long size)
{
	ft_queue *q;
	q = (ft_queue *)calloc (1,sizeof (ft_queue));
	if (q == NULL) return (NULL);
	void **buff = (void **)calloc(size, sizeof(void *));
	q->buf = buff; 
	q->size = size;
	q->empty = 1;
	q->full = 0;
	q->head = 0;
	q->tail = 0;
	q->mut = (pthread_mutex_t *) malloc (sizeof (pthread_mutex_t));
	pthread_mutex_init (q->mut, NULL);
	q->not_full = (pthread_cond_t *) malloc (sizeof (pthread_cond_t));
	pthread_cond_init (q->not_full, NULL);
	q->not_empty = (pthread_cond_t *) malloc (sizeof (pthread_cond_t));
	pthread_cond_init (q->not_empty, NULL);
	
	return (q);
}

inline void queue_destroy (ft_queue *q)
{
	pthread_mutex_destroy (q->mut);
	free (q->mut);	
	pthread_cond_destroy (q->not_full);
	free (q->not_full);
	pthread_cond_destroy (q->not_empty);
	free (q->not_empty);
	free (q);
}

inline void queue_push (ft_queue *q, void *in)
{
	q->buf[q->tail] = in;
	q->tail++;
	if (q->tail == q->size)
		q->tail = 0;
	if (q->tail == q->head)
		q->full = 1;
	q->empty = 0;
	return;
}

inline void queue_pop (ft_queue *q, void **out)
{
	*out = q->buf[q->head];

	q->head++;
	if (q->head == q->size)
		q->head = 0;
	if (q->head == q->tail)
		q->empty = 1;
	q->full = 0;

	return;
}

inline void pq_push (heap_t *h, int priority, void * data) {
    if (h->len + 1 >= h->size) {
        h->size = h->size ? h->size * 2 : 4;
        h->nodes = (node_pq *)realloc(h->nodes, h->size * sizeof (node_pq));
    }
    int i = h->len + 1;
    int j = i / 2;
    while (i > 1 && h->nodes[j].priority < priority) {
        h->nodes[i] = h->nodes[j];
        i = j;
        j = j / 2;
    }
    h->nodes[i].priority = priority;
    h->nodes[i].data = data;
    h->len++;
}

inline void *pq_pop (heap_t *h) {
    int i, j, k;
    if (!h->len) {
        return NULL;
    }
    void * data = h->nodes[1].data;

    h->nodes[1] = h->nodes[h->len];

    h->len--;

    i = 1;
    while (i!=h->len+1) {
        k = h->len+1;
        j = 2 * i;
        if (j <= h->len && h->nodes[j].priority > h->nodes[k].priority) {
            k = j;
        }
        if (j + 1 <= h->len && h->nodes[j + 1].priority > h->nodes[k].priority) {
            k = j + 1;
        }
        h->nodes[i] = h->nodes[k];
        i = k;
    }
    return data;
}

#ifdef __cplusplus
}
#endif
#endif
