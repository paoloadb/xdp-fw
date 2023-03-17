# xdp-fw
go firewall using xdp
I used the go ebpf library by Dropbox

to compile .c file to .elf:
`clang -I ../headers -O -target bpf -c xdp.c -o xdp.elf`
