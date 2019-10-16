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
#include "devices/input.h"
#include "userprog/pagedir.h"


static void syscall_handler (struct intr_frame *);
struct file* search_file_by_inode(struct inode *inode);
void bad_ptr_exception(void* ptr);


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
      // if (!is_user_vaddr(*(uint32_t *)((f->esp)+4)) || !is_user_vaddr(*(uint32_t *)((f->esp)+4))
      //     || !is_user_vaddr(*(uint32_t *)((f->esp)+4))){
      //   printf("here?\n");
      //   sys_exit(-1);
      // }
      read_size = sys_read((int)*(uint32_t *)((f->esp)+4), (void *)*(uint32_t *)((f->esp)+8),
        (unsigned)*(uint32_t *)((f->esp)+12));
      f->eax = read_size;
      break;

    case SYS_WRITE:
      // if (!is_user_vaddr(*(uint32_t *)((f->esp)+4)) || !is_user_vaddr(*(uint32_t *)((f->esp)+4))
      //     || !is_user_vaddr(*(uint32_t *)((f->esp)+4))){
      //   printf("here?!?@!?!??\n");
      //   sys_exit(-1);
      // }
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

void bad_ptr_exception(void* ptr){
  struct thread *cur = thread_current();
  uint32_t *pd = cur-> pagedir;
  if(ptr==NULL || !is_user_vaddr(ptr) || pagedir_get_page(pd, ptr)==NULL)
    sys_exit(-1);
}

void 
sys_exit (int status){
  struct thread* cur = thread_current();
  if(cur->parent_thread != NULL){
    cur->exit_status = status;
    //file_allow_write(thread_current()->execute_file);
    lock_acquire(&filesys_lock);
    file_close(cur->execute_file);
    lock_release(&filesys_lock);
    sema_up(&cur->sema);
  }
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
  
}

pid_t 
sys_exec (const char *cmd_line){

  struct thread* cur = thread_current ();

  tid_t child_tid = process_execute (cmd_line);
  sema_down(&cur->load_sema);


  if(cur->is_load_successful) {
    return (pid_t) child_tid;
  }
  else {
    return (pid_t) -1;
  }

}

int 
sys_wait (pid_t pid){

  struct thread* cur = thread_current ();

  //sema_down(&cur->wait_sema);

  int exit_status = -1;

  exit_status = process_wait((tid_t) pid);
  


  return exit_status;
}

bool sys_create (const char *file, unsigned initial_size){

  bad_ptr_exception(file);

  lock_acquire(&filesys_lock);
  bool create_bool = filesys_create(file, initial_size);
  lock_release(&filesys_lock);

  return create_bool;
}

bool sys_remove (const char *file){
  
  bad_ptr_exception(file);

  lock_acquire(&filesys_lock);
  bool remove_bool = filesys_remove(file);
  lock_release(&filesys_lock);
  return remove_bool;
}

int sys_open (const char *file){

  bad_ptr_exception(file);

  struct thread* cur = thread_current ();

  lock_acquire(&filesys_lock);
  struct file* opened_file = filesys_open (file);
  lock_release(&filesys_lock);

  if(opened_file == NULL) return -1;
  opened_file->file_fd = cur->fd;
  opened_file->open = true;
  lock_acquire(&file_list_lock);
  list_push_back(&cur->file_list, &opened_file->file_elem);
  lock_release(&file_list_lock);
  cur->fd++;
  return opened_file->file_fd;

  
  

}

struct file* search_file(int fd){
  struct thread* cur = thread_current();
  struct file* file_to_read = NULL;
  lock_acquire(&file_list_lock);
  
  if(!list_empty(&cur->file_list)){
    struct list_elem *fe;
    for (fe = list_begin (&cur->file_list); fe != list_end (&cur->file_list);
            fe = list_next (fe))
    {
      struct file *f = list_entry (fe, struct file, file_elem);
      if (f->file_fd == fd){
        file_to_read = f;
        break;
      }
    }
  }

  lock_release(&file_list_lock);
  return file_to_read;
}

struct file* search_file_by_inode(struct inode *inode){
  struct thread* cur = thread_current();
  struct file* file_to_read = NULL;
  lock_acquire(&file_list_lock);
  
  if(!list_empty(&cur->file_list)){
    struct list_elem *fe;
    for (fe = list_begin (&cur->file_list); fe != list_end (&cur->file_list);
            fe = list_next (fe))
    {
      struct file *f = list_entry (fe, struct file, file_elem);
      if (f->inode == inode){
        file_to_read = f;
        break;
      }
    }
  }
  lock_release(&file_list_lock);
  return file_to_read;
}

int sys_filesize (int fd){

  struct file* file = search_file(fd);
  if(file==NULL)  return -1;
  off_t filesize = file_length(file);
  
  return (int) filesize;
}

int sys_read (int fd, void *buffer, unsigned size){

  bad_ptr_exception(buffer);


  int read_size;

  if(fd==0) {
    read_size = input_getc();
  }
  else{
    struct file* file_to_read = search_file(fd);
    if(file_to_read == NULL) return -1;
    if(file_to_read->open == false) return -1;
    lock_acquire(&filesys_lock);    
    read_size = (int)file_read(file_to_read, buffer, size);
    lock_release(&filesys_lock);
  }
  return read_size;
}

int 
sys_write (int fd, const void *buffer, unsigned size){

  bad_ptr_exception(buffer);

  if(fd==1){ // Writes to console
    putbuf(buffer, size);
    return size;
  }
  else{ 
    struct file *file_to_write = search_file(fd);
    if(file_to_write==NULL) return -1;
    if(file_to_write->open == false) return -1;
    if(file_to_write->deny_write) return 0;

    lock_acquire(&filesys_lock);
    off_t write_size = file_write(file_to_write, buffer, size);
    lock_release(&filesys_lock);

    return (int)write_size;
  }
}

void sys_seek (int fd, unsigned position){
  struct file *file_to_seek = search_file(fd);
  lock_acquire(&filesys_lock);  
  file_seek(file_to_seek, position);
  lock_release(&filesys_lock);
  return;
}

unsigned sys_tell (int fd){
  struct file *file_to_tell = search_file(fd);
  lock_acquire(&filesys_lock);
  off_t pos = file_tell(file_to_tell);
  lock_release(&filesys_lock);
  
  return (int) pos;
}

void sys_close (int fd){
  struct file *file_to_close = search_file(fd);
  if(file_to_close == NULL || file_to_close->open == false)
  {
    sys_exit(-1);
  }
  
  file_to_close->open = false;
  list_remove(&file_to_close->file_elem);

  lock_acquire(&filesys_lock);
  file_close(file_to_close);
  lock_release(&filesys_lock);
  

  return;
}
