
rule Trojan_Win64_ShellcodeRunner_SXH_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.SXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_80_0 = {50 72 65 73 73 20 3c 45 6e 74 65 72 3e 20 54 6f 20 45 78 65 63 75 74 65 20 54 68 65 20 50 61 79 6c 6f 61 64 } //Press <Enter> To Execute The Payload  10
		$a_80_1 = {45 78 65 63 75 74 69 6e 67 20 27 73 79 73 63 61 6c 6c 27 20 69 6e 73 74 72 75 63 74 69 6f 6e 20 4f 66 20 41 64 64 72 65 73 73 20 3a 20 30 78 25 70 } //Executing 'syscall' instruction Of Address : 0x%p  5
		$a_80_2 = {5b 2b 5d 20 53 79 73 63 61 6c 6c 20 4e 75 6d 62 65 72 20 4f 66 20 4e 74 41 6c 6c 6f 63 61 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 20 49 73 20 3a 20 30 78 25 30 2e 32 58 } //[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x%0.2X  2
		$a_80_3 = {50 72 65 73 73 20 3c 45 6e 74 65 72 3e 20 54 6f 20 51 75 69 74 } //Press <Enter> To Quit  2
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=19
 
}