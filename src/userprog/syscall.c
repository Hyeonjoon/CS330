#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "lib/user/syscall.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"


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
  int exit_status, open, filesize, read_size, write_size;
  unsigned tell;
  bool create, remove;

  switch(*(uint32_t *)(f->esp)){
    case SYS_HALT:
      shutdown_power_off();
      break;

    case SYS_EXIT:
      status = (uint32_t)*(uint32_t *)((f->esp)+4);
      if (!is_user_vaddr(status)){
        sys_exit(-1);
      }
      else{
        sys_exit(status);
      }
      NOT_REACHED ();
      break;

    case SYS_EXEC:
      pid = sys_exec((char *)*(char **)((f->esp)+4));
      f->eax = pid;
      break;

    case SYS_WAIT:
      exit_status = sys_wait(*(int *)((f->esp)+4));
      f->eax = exit_status;
      break;

    case SYS_CREATE:
      create = sys_create(*(char **)((f->esp)+4), *(unsigned *)((f->esp)+8));
      f->eax = create;
      break;

    case SYS_REMOVE:
      remove = sys_remove( *(char **)((f->esp)+4) );
      f->eax = remove;
      break;

    case SYS_OPEN:
      open = sys_open( *(char **)((f->esp)+4) );
      f->eax = open;
      break;

    case SYS_FILESIZE:
      filesize = sys_filesize( *(int *)((f->esp)+4) );
      f->eax = filesize;
      break;

    case SYS_READ:
      read_size = sys_read((int)*(uint32_t *)((f->esp)+4), (void *)*(uint32_t *)((f->esp)+8),
        (unsigned)*(uint32_t *)((f->esp)+12));
      f->eax = read_size;
      break;

    case SYS_WRITE:
      write_size = sys_write((int)*(uint32_t *)((f->esp)+4), (void *)*(uint32_t *)((f->esp)+8),
        (unsigned)*(uint32_t *)((f->esp)+12));
      f->eax = write_size;
      break;

    case SYS_SEEK:
      sys_seek(*(int *)((f->esp)+4), *(unsigned *)((f->esp)+8));
      break;

    case SYS_TELL:
      tell = sys_tell(*(int *)((f->esp)+4));
      f->eax = tell;
      break;

    case SYS_CLOSE:
      sys_close(*(int *)((f->esp)+4));
      break;


    default:
      printf("Not matched");
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

void 
sys_exit (int status){

  if(thread_current()->parent_thread != NULL){
    thread_current()->exit_status = status;
    sema_up(&thread_current()->sema);
    sema_up(&thread_current()->parent_thread->child_sema);
  }
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit ();
  
}

pid_t 
sys_exec (const char *cmd_line){

  struct thread* cur = thread_current ();

  tid_t child_tid = process_execute (cmd_line);
  sema_down(&cur->child_sema);


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

  exit_status = process_wait((tid_t) pid);

  return exit_status;
}

bool sys_create (const char *file, unsigned initial_size){
  if(file==NULL){
    sys_exit(-1);
    NOT_REACHED();
  }
  bool create_bool = filesys_create(file, initial_size);

  return create_bool;
}

bool sys_remove (const char *file){
  bool remove_bool = filesys_remove(file);
  return remove_bool;
}
int sys_open (const char *file){

  if(file==NULL) return -1;
  struct thread* cur = thread_current ();
  struct file* opened_file = filesys_open (file);
  if(opened_file == NULL) return -1;
  opened_file->file_fd = cur->fd;
  list_push_back(&cur->file_list, &opened_file->file_elem);
  cur->fd++;
  return opened_file->file_fd;

}
int sys_filesize (int fd){
  return -1;
}
int sys_read (int fd, void *buffer, unsigned size){
  return -1;
}
void sys_seek (int fd, unsigned position){
  return;
}
unsigned sys_tell (int fd){
  return -1;
}
void sys_close (int fd){
  return;
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
