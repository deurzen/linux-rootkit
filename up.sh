#!/usr/bin/env bash

while (( "$#" )); do
  case "$1" in
    -h|--help)
      echo "$(basename $0): start RKP QEMU instance"
      echo "options:"
      echo "   --debug: have QEMU listen to an incoming gdb connection on :1234"
      echo "   --block: block before QEMU start"
      exit
      ;;
    --init)
      INITREPO=1
      shift
      ;;
    --debug)
      PARAMS="$PARAMS -s"
      GDBSET=1
      shift
      ;;
    --block)
      PARAMS="$PARAMS -S"
      BLOCKSET=1
      shift
      ;;
    --ssh)
      EXPECTSSH=1
      shift
      ;;
    --)
      shift
      break
      ;;
    -*|--*=)
      >&2 echo "invalid option: $1"
      exit 1
      ;;
    *)
      PARAMS="$PARAMS $1"
      shift
      ;;
  esac
done

if ! test -z $INITREPO; then
  if ! test -e ./debian-10.6.0-amd64-netinst.iso; then
    wget https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-10.6.0-amd64-netinst.iso
  fi

  if ! test -e ./linux-image-4.19.0-12-amd64-dbg_4.19.152-1_amd64.deb; then
    wget http://security.debian.org/debian-security/pool/updates/main/l/linux/linux-image-4.19.0-12-amd64-dbg_4.19.152-1_amd64.deb
  fi

  if ! test -e ./debian.img; then
    qemu-img create -f qcow2 debian.img 20G
    qemu-system-x86_64 -hda debian.img -cdrom debian-10.6.0-amd64-netinst.iso -boot d -m 4096
  fi

  echo "!!! add nokaslr to GRUB_CMDLINE_LINUX_DEFAULT and"
  echo "!!! set GRUB_HIDDEN_TIMEOUT=0 and GRUB_HIDDEN_TIMEOUT_QUIET=true"
  echo "!!! in /etc/default/grub, then run grub-mkconfig"
fi

if ! test -z $BLOCKSET && test -z $GDBSET; then
    >&2 echo "--debug flag must be set with --block"
    exit 1
fi

qemu-system-x86_64 $PARAMS -hda debian.img -m 4096 -enable-kvm -cpu host -device e1000,netdev=net0 -netdev user,id=net0,hostfwd=tcp::2222-:22 &

if ! test -z $GDBSET; then
  test -z $EXPECTSSH || st -e ./ssh.expect &
  exec sh -c 'gdb -q -ex "target remote :1234"'
else
  test -z $EXPECTSSH || exec ./ssh.expect
fi
