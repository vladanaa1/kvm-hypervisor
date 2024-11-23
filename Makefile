
all: guest.img hypervisor

hypervisor: hypervisor.c
	gcc hypervisor.c -o hypervisor

guest.img: guest.o
	ld -T guest.ld guest.o -o guest.img

guest.o: guest.c
	$(CC) -m64 -ffreestanding -fno-pic -c -o $@ $^

clean:
	rm -f hypervisor guest.o guest.img