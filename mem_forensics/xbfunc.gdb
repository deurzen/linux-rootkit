define xbfunc
    dont-repeat

    set $addr = (char *)($arg0)
    set $end = $addr + $arg1

    while $addr < $end
		printf "%02x ", *(unsigned char *)$addr
		set $addr++
    end
end

document xbfunc
usage: xbfunc addr n
outputs n bytes in hex (without leading 0x), starting at addr
end
