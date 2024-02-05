
rule Trojan_Win32_NimCryptPacker_A{
	meta:
		description = "Trojan:Win32/NimCryptPacker.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {40 5b 2a 5d 20 46 6f 75 6e 64 20 53 79 73 63 61 6c 6c 20 53 74 75 62 3a 20 } //@[*] Found Syscall Stub:   01 00 
		$a_80_1 = {66 61 74 61 6c 2e 6e 69 6d } //fatal.nim  01 00 
		$a_80_2 = {68 61 73 68 63 6f 6d 6d 6f 6e 2e 6e 69 6d } //hashcommon.nim  00 00 
	condition:
		any of ($a_*)
 
}