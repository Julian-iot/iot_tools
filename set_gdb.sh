set architecture mips
set follow-fork-mode parent
set detach-on-fork on
target remote 192.168.88.11:1234
# handle SIGBUS  nostop noprint pass
handle SIGSEGV nostop noprint
b *0x004CC38C
c