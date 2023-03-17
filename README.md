# xdp-fw
go firewall using xdp

to compile .c file to .elf:
`clang -I ../headers -O -target bpf -c xdp.c -o xdp.elf`
