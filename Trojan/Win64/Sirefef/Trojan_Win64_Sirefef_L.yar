
rule Trojan_Win64_Sirefef_L{
	meta:
		description = "Trojan:Win64/Sirefef.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 81 f8 73 65 6e 64 74 90 01 01 41 81 f8 72 65 63 76 74 90 14 45 85 c9 90 00 } //1
		$a_00_1 = {5c 78 36 34 5c 72 65 6c 65 61 73 65 5c 73 68 65 6c 6c 2e 70 64 62 } //1 \x64\release\shell.pdb
		$a_01_2 = {81 7f 54 7f 00 00 01 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_L_2{
	meta:
		description = "Trojan:Win64/Sirefef.L,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 81 f8 73 65 6e 64 74 90 01 01 41 81 f8 72 65 63 76 74 90 14 45 85 c9 90 00 } //1
		$a_00_1 = {5c 78 36 34 5c 72 65 6c 65 61 73 65 5c 73 68 65 6c 6c 2e 70 64 62 } //1 \x64\release\shell.pdb
		$a_01_2 = {81 7f 54 7f 00 00 01 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}