
rule Trojan_Win64_Tedy_LRC_MTB{
	meta:
		description = "Trojan:Win64/Tedy.LRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_81_0 = {5b 2b 5d 45 78 65 63 75 74 69 6e 67 20 73 68 65 6c 6c 63 6f 64 65 2e 2e 2e 2e } //1 [+]Executing shellcode....
		$a_81_1 = {52 65 6c 65 61 73 65 5c 4d 59 46 49 52 53 54 4d 41 4c 57 41 52 45 } //2 Release\MYFIRSTMALWARE
		$a_81_2 = {5b 2a 5d 20 41 6c 6c 20 63 68 75 6e 6b 73 20 77 72 69 74 74 65 6e 2e } //3 [*] All chunks written.
		$a_81_3 = {5b 2a 5d 20 57 72 6f 74 65 } //4 [*] Wrote
		$a_81_4 = {5b 2a 5d 20 41 6c 6c 6f 63 61 74 65 64 20 6d 65 6d 6f 72 79 20 61 74 3a } //5 [*] Allocated memory at:
		$a_81_5 = {73 65 63 72 65 74 } //6 secret
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6) >=21
 
}