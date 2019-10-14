#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/user/syscall.h"
#include "threads/vaddr.h"
#include "threads/synch.h"


static void syscall_handler (struct intr_frame *);
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  uint32_t status;
  pid_t pid;
  int size;

  switch(*(uint32_t *)(f->esp)){
    case SYS_HALT:
      //printf("SYS_HALT\n");
      break;
    case SYS_EXIT:
      //printf("SYS_EXIT\n");
      
      status = (uint32_t)*(uint32_t *)((f->esp)+4);
      if (!is_user_vaddr(status)){
        sys_exit(-1);
      }
      else{
        sys_exit(status);
      }
      // exit((int)*(uint32_t *)((f->esp)+4));
      NOT_REACHED ();
      break;
    case SYS_EXEC:
      
      pid = sys_exec((char *)*(char **)((f->esp)+4));
      f->eax = pid;
      //printf("SYS_EXEC\n");
      break;
    case SYS_WAIT:
      //sys_wait(*(int *)((f->esp)+4));
      //printf("SYS_WAIT\n");
      break;
    case SYS_CREATE:
      //printf("SYS_CREATE\n");
      break;
    case SYS_REMOVE:
      //printf("SYS_REMOVE\n");
      break;
    case SYS_OPEN:
      //printf("SYS_OPEN\n");
      break;
    case SYS_FILESIZE:
      //printf("SYS_FILESIZE\n");
      break;
    case SYS_READ:
      //printf("SYS_READ\n");
      break;
    case SYS_WRITE:
      //printf("SYS_WRITE\n");
      // printf("addr1 : %x\n", (int)((f->esp)+4));
      // printf("%d\n", (int)*(uint32_t *)((f->esp)+4));
      // printf("addr2 : %x\n", (int)((f->esp)+8));
      // printf("%s\n", (char *)*(uint32_t *)((f->esp)+8));
      // printf("%x\n", (char *)*(uint32_t *)((f->esp)+8));
      // printf("addr3 : %x\n", (int)((f->esp)+12));
      // printf("%d\n", (unsigned)*(uint32_t *)((f->esp)+12));
      
      // if( put_user((uint8_t *)*(uint8_t **)((f->esp)+8), (uint8_t)*(uint8_t *)((f->esp)+12)) ){
      //   printf("True\n");
      // }
      // else{
      //   printf("False\n");
      // }
      
      size = sys_write((int)*(uint32_t *)((f->esp)+4), (void *)*(uint32_t *)((f->esp)+8),
        (unsigned)*(uint32_t *)((f->esp)+12));
      f->eax = size;
      break;
    case SYS_SEEK:
      //printf("SYS_SEEK\n");
      break;
    case SYS_TELL:
      //printf("SYS_TELL\n");
      break;
    case SYS_CLOSE:
      //printf("SYS_CLOSE\n");
      break;


    default:
      //printf("Not matched");
      break;
  }

  //thread_exit ();
}

int 
sys_write (int fd, const void *buffer, unsigned size){
  if(fd==1){ // Writes to console
    putbuf(buffer, size);
    return size;
  }
  else{ 
    return 999;
  }
}

struct process{
  pid_t pid;
  struct list_elem p_elem;
};

void 
sys_exit (int status){

  // if(thread_current()->parent_thread != NULL){
  //   sys_exit(sys_wait((pid_t)thread_current()->tid));
  // }
  // else{
  //   printf("%s: exit(%d)\n", thread_current()->name, status);
  //   thread_exit ();
  // }
  if(thread_current()->parent_thread != NULL){
    sema_up(&thread_current()->parent_thread->child_sema);
  }
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit ();
  
}

pid_t 
sys_exec (const char *cmd_line){

  struct thread* cur = thread_current ();
  struct process p;


  tid_t child_tid = process_execute (cmd_line);
  sema_down(&cur->child_sema);

  

  // pid_t pid = (pid_t) child_tid;
  // p.pid = pid;
  // list_push_back(&cur->child_list, &p.p_elem);


  if(cur->is_load_successful) {
    return (pid_t) child_tid;
  }
  else {
    return (pid_t) -1;
  }

}

int 
sys_wait (pid_t pid){

  int exit_status = -1;

  // if(!list_empty(&thread_current()->child_list)){
  //   struct list_elem *c;
  //   for (c = list_begin (&thread_current()->child_list); c != list_end (&thread_current()->child_list);
  //           c = list_next (c))
  //   {
  //     struct process *p = list_entry (c, struct process, p_elem);
  //     if (p->pid == pid){
        
  //       list_remove(&p->p_elem);
  //     }
  //   }
  // }


  return exit_status;
}



/* Read a byte at user virtual address UADDR.
Returns byte value if successful, -1 if segmant fault occured. */
static int
get_user(const uint8_t *uaddr){
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}
/* Write BYTE to user address UDST.
Return true if successful, false if a segmant fault occurred. */
static bool
put_user(uint8_t *udst, uint8_t byte){
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code) , "=m" (*udst) : "q" (byte));
  return error_code != -1;
}
