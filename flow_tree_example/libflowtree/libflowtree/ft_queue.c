#include "ft_queue.h"
extern inline ft_stack * stack_new(long size);
extern inline void stack_destroy(ft_stack * s);
extern inline void stack_push(ft_stack *s, void *in);
extern inline void stack_pop(ft_stack *s, void **out);
extern inline void stack_peek(ft_stack *s, void **out); 

extern inline ft_queue * queue_new (long size);
extern inline void queue_destroy (ft_queue *q);
extern inline void queue_push (ft_queue *q, void *in);
extern inline void queue_pop (ft_queue *q, void **out);

extern inline void pq_push (heap_t *h, int priority, void * data);
extern inline void *pq_pop (heap_t *h);   

