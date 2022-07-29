CC := gcc 
CFLAGS := -m32 -std=gnu99 -g -O0 -no-pie -fno-stack-protector -fno-PIE -fno-pie -fno-stack-check 
ALL := ex1 

all: $(ALL)

ex1: ex1.c
	$(CC) $(CFLAGS) -o $@ $< -ldl

clean:
	rm -f $(ALL)

.PHONY: all clean
