# xdp-fw
a Level 3 go firewall using xdp  
Based on the go ebpf library by Dropbox

to compile .c file to .elf:  
`clang -I ../headers -O -target bpf -c xdp-<black or white>.c -o xdp-<black or white>.elf`  
to build go:   
`go build main.go`
