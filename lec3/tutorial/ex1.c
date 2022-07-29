#define _GNU_SOURCE
#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

void spawn_shell(){
	printf("There you are!\n");
	setregid(getegid(), getegid());
	execl("/bin/bash", "bash", NULL);
}

void read_input() {
	char buf[32];
	memset(buf, 0, sizeof(buf));
	read(0, buf, 44);

	if (!strcmp(buf, "Password"))
		printf("Password OK :)\n");
	else
		printf("Invalid Password!\n");
}

void run(){	
	read_input();	
}


int main(int argc, char *argv[]){
	setvbuf(stdout, NULL, _IONBF, 0);
  	setvbuf(stdin, NULL, _IONBF, 0);

	void *self = dlopen(NULL, RTLD_NOW);
	printf("stack: %p\n", &argc);

	printf("What is your password: ");
	run();
	return 0;
}
