
rule Trojan_Win64_ShellcodeRunner_RO_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 33 39 33 39 32 5c 4f 6e 65 44 72 69 76 65 5c 44 65 73 6b 74 6f 70 5c 54 65 73 74 31 5c 78 36 34 5c 44 65 62 75 67 5c 54 65 73 74 31 2e 70 64 62 } //5 C:\Users\39392\OneDrive\Desktop\Test1\x64\Debug\Test1.pdb
		$a_01_1 = {25 73 25 73 25 70 25 73 25 7a 64 25 73 25 64 25 73 25 73 25 73 25 73 25 73 } //2 %s%s%p%s%zd%s%d%s%s%s%s%s
		$a_01_2 = {53 74 61 63 6b 20 70 6f 69 6e 74 65 72 20 63 6f 72 72 75 70 74 69 6f 6e } //1 Stack pointer corruption
		$a_01_3 = {53 74 61 63 6b 20 6d 65 6d 6f 72 79 20 63 6f 72 72 75 70 74 69 6f 6e } //1 Stack memory corruption
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=9
 
}