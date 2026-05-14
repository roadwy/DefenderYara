
rule Trojan_Win64_CobaltStrike_NTA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.NTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_02_0 = {5c 00 69 00 6e 00 63 00 65 00 70 00 74 00 6f 00 72 00 5c 00 69 00 6e 00 63 00 65 00 70 00 74 00 6f 00 72 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-50] 2e 00 70 00 64 00 62 00 } //3
		$a_02_1 = {5c 69 6e 63 65 70 74 6f 72 5c 69 6e 63 65 70 74 6f 72 5c 74 65 6d 70 5c [0-50] 2e 70 64 62 } //3
		$a_81_2 = {5b 2b 5d 20 54 68 65 20 73 68 65 6c 6c 63 6f 64 65 20 66 69 6e 69 73 68 65 64 20 77 69 74 68 20 61 20 72 65 74 75 72 6e 20 76 61 6c 75 65 3a 20 25 30 38 58 } //1 [+] The shellcode finished with a return value: %08X
		$a_81_3 = {5b 2a 5d 20 41 6c 6c 6f 63 61 74 69 6e 67 20 25 64 20 62 79 74 65 73 20 6f 66 20 6d 65 6d 6f 72 79 } //1 [*] Allocating %d bytes of memory
		$a_81_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_81_5 = {5b 2a 5d 20 45 78 65 63 75 74 69 6e 67 } //1 [*] Executing
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*3+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}