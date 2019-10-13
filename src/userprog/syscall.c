#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/user/syscall.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  //printf ("system call!\n");
  //printf("esp : %d\n", *(uint32_t *)(f->esp));
  switch(*(uint32_t *)(f->esp)){
    case SYS_HALT:
      printf("SYS_HALT\n");
      break;
    case SYS_EXIT:
      //printf("SYS_EXIT\n");
      exit((int)*(uint32_t *)((f->esp)+4));
      NOT_REACHED ();
      break;
    case SYS_EXEC:
      printf("SYS_EXEC\n");
      break;
    case SYS_WAIT:
      printf("SYS_WAIT\n");
      break;
    case SYS_CREATE:
      printf("SYS_CREATE\n");
      break;
    case SYS_REMOVE:
      printf("SYS_REMOVE\n");
      break;
    case SYS_OPEN:
      printf("SYS_OPEN\n");
      break;
    case SYS_FILESIZE:
      printf("SYS_FILESIZE\n");
      break;
    case SYS_READ:
      printf("SYS_READ\n");
      break;
    case SYS_WRITE:
      // printf("SYS_WRITE\n");
      // printf("addr1 : %x\n", (int)((f->esp)+4));
      // printf("%d\n", (int)*(uint32_t *)((f->esp)+4));
      // printf("addr2 : %x\n", (int)((f->esp)+8));
      // printf("%x\n", (void *)*(uint32_t *)((f->esp)+8));
      // printf("addr3 : %x\n", (int)((f->esp)+12));
      // printf("%d\n", (unsigned)*(uint32_t *)((f->esp)+12));
      write((int)*(uint32_t *)((f->esp)+4), (void *)*(uint32_t *)((f->esp)+8),
        (unsigned)*(uint32_t *)((f->esp)+12));
      break;
    case SYS_SEEK:
      printf("SYS_SEEK\n");
      break;
    case SYS_TELL:
      printf("SYS_TELL\n");
      break;
    case SYS_CLOSE:
      printf("SYS_CLOSE\n");
      break;


    default:
      printf("Not matched");
      break;
  }

  //thread_exit ();
}

int 
write (int fd, const void *buffer, unsigned size){
  if(fd==1){ // Writes to console
    putbuf(buffer, size);
    return size;
  }
  else{
    return 999;
  }
}

void 
exit (int status){
  if (status==0){
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit ();
  }
}

