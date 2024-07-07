
rule Trojan_BAT_ShellInject_NEAB_MTB{
	meta:
		description = "Trojan:BAT/ShellInject.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {13 06 11 04 11 05 11 06 28 07 00 00 06 13 07 20 3a 04 00 00 16 09 28 01 00 00 06 13 08 11 08 7e 0c 00 00 0a 11 07 8e 69 20 00 30 00 00 1f 40 28 03 00 00 06 13 09 11 08 11 09 11 07 11 07 8e 69 12 0a 28 04 00 00 06 } //10
		$a_01_1 = {44 65 63 72 79 70 74 53 68 65 6c 6c 63 6f 64 65 } //2 DecryptShellcode
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //2 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}