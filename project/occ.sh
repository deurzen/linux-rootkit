#!/bin/bash
#extract all occurences of function calls and the assigned variables from kernel sources

#these are (more or less) wrappers for the functions we use in livedm.py
funcs=("kmalloc" "kzalloc" "vmalloc" "vzalloc" "alloc_task_struct_node")
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

old_pwd=$PWD

cd $1
find  . \
    -name "*.[chxsS]" -print > ./cscope.files
echo "Done!"

echo "Generating occurence database.."
for f in ${funcs[@]}; do
    cscope -L -0 $f >> $out
done
echo "Done!"

mv $out $old_pwd
