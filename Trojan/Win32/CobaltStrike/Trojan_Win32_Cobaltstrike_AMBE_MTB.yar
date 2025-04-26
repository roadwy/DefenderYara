
rule Trojan_Win32_Cobaltstrike_AMBE_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_80_0 = {4e 6f 20 64 62 67 20 77 61 73 20 64 65 74 65 63 74 65 64 20 72 75 6e 6e 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 } //No dbg was detected running shellcode  1
		$a_80_1 = {72 65 6d 6f 74 65 20 64 62 67 20 69 73 20 72 75 6e 6e 69 6e 67 } //remote dbg is running  1
		$a_80_2 = {6c 6f 63 61 6c 20 64 62 67 20 69 73 20 72 75 6e 6e 69 6e 67 } //local dbg is running  1
		$a_80_3 = {64 62 67 20 69 73 20 64 69 73 61 62 6c 65 64 } //dbg is disabled  1
		$a_80_4 = {4b 44 42 3a 20 44 69 73 61 62 6c 65 64 } //KDB: Disabled  1
		$a_80_5 = {42 79 70 61 73 73 5f 41 56 2e 70 64 62 } //Bypass_AV.pdb  1
		$a_80_6 = {5b 2b 5d 20 42 79 74 65 20 30 78 25 58 20 77 72 6f 74 65 20 73 75 63 65 73 73 66 75 6c 6c 79 21 20 61 74 20 30 78 } //[+] Byte 0x%X wrote sucessfully! at 0x  1
		$a_80_7 = {5b 2b 5d 20 70 72 6f 63 65 73 73 20 6f 70 65 6e 65 64 20 2d 20 48 61 6e 64 6c 65 20 76 61 6c 75 65 20 69 73 } //[+] process opened - Handle value is  1
		$a_80_8 = {5b 2b 5d 20 54 68 65 20 74 68 72 65 61 64 20 66 69 6e 69 73 68 65 64 21 } //[+] The thread finished!  1
		$a_80_9 = {5b 2b 5d 20 52 75 6e 6e 69 6e 67 20 74 68 65 20 74 68 72 65 61 64 } //[+] Running the thread  1
		$a_80_10 = {5b 2b 5d 20 4d 65 6d 6f 72 79 20 41 6c 6c 6f 63 61 74 65 64 } //[+] Memory Allocated  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=11
 
}