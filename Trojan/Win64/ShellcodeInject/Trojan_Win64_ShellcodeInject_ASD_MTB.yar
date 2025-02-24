
rule Trojan_Win64_ShellcodeInject_ASD_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.ASD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {6d 73 65 64 67 65 77 68 69 74 65 2e 72 74 7a } //1 msedgewhite.rtz
		$a_81_1 = {46 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 20 61 6e 64 20 65 78 65 63 75 74 65 20 73 68 65 6c 6c 63 6f 64 65 } //1 Failed to load and execute shellcode
		$a_81_2 = {44 6c 6c 34 2e 70 64 62 } //1 Dll4.pdb
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}