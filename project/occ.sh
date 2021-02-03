#!/bin/bash
#Extract all occurences of function calls and the assigned variables from kernel sources
funcs=("kmalloc" "kzalloc" "kfree")
out=".funcs"

rm -f cscope.out cscope.files $out

for f in ${funcs[@]}; do
    rm -f $f
done

if [ $# -eq 0 ]; then
    echo "Usage: $0 <kernel src dir>"
    exit 0
fi

if ! [ -x "$(command -v cscope)" ]; then
    echo 'Dependency cscope is missing.' >&2
    exit 1
fi

echo "Generating file cscope.files.."
find  $1 \
	-path "$1arch/alpha*" -prune -o \
	-path "$1arch/arc*" -prune -o \
	-path "$1arch/arm*" -prune -o \
	-path "$1arch/arm64*" -prune -o \
	-path "$1arch/c6x*" -prune -o \
	-path "$1arch/h8300*" -prune -o \
	-path "$1arch/hexagon*" -prune -o \
	-path "$1arch/ia64*" -prune -o \
	-path "$1arch/m68k*" -prune -o \
	-path "$1arch/microblaze*" -prune -o \
	-path "$1arch/mips*" -prune -o \
	-path "$1arch/nds32*" -prune -o \
	-path "$1arch/nios2*" -prune -o \
	-path "$1arch/openrisc*" -prune -o \
	-path "$1arch/parisc*" -prune -o \
	-path "$1arch/powerpc*" -prune -o \
	-path "$1arch/riscv*" -prune -o \
	-path "$1arch/s390*" -prune -o \
	-path "$1arch/sh*" -prune -o \
	-path "$1arch/sparc*" -prune -o \
	-path "$1arch/um*" -prune -o \
	-path "$1arch/unicore32*" -prune -o \
	-path "$1arch/xtensa*" -prune -o \
	-path "$1drivers*" -prune -o \
    -path "$1Documentation*" -prune -o \
    -path "$1scripts*" -prune -o \
    -path "$1tools*" -prune -o \
    -name "*.[chxsS]" -print > ./cscope.files
echo "Done!"

echo "Generating occurence database.."
echo "$1" >> $out
for f in ${funcs[@]}; do
    cscope -L -0 $f >> $out
done
echo "Done!"