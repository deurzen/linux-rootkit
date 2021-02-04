#!/bin/bash
#Extract all occurences of function calls and the assigned variables from kernel sources
funcs=("kmalloc" "kzalloc")
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
    -name "*.[chxsS]" -print > ./cscope.files
echo "Done!"

echo "Generating occurence database.."
echo "$1" >> $out
for f in ${funcs[@]}; do
    cscope -L -0 $f >> $out
done
echo "Done!"