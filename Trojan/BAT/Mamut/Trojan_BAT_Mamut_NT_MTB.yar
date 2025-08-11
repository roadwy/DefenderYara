
rule Trojan_BAT_Mamut_NT_MTB{
	meta:
		description = "Trojan:BAT/Mamut.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 36 00 00 0a 7e 01 00 00 04 02 1a 58 08 6f 37 00 00 0a 28 38 00 00 0a a5 01 00 00 1b 0b 11 08 20 e5 35 0c 49 5a 20 38 6c 42 4a 61 } //3
		$a_01_1 = {41 75 74 6f 6b 65 6f 78 65 2e 70 64 62 } //1 Autokeoxe.pdb
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}