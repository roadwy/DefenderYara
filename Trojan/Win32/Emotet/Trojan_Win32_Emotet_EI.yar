
rule Trojan_Win32_Emotet_EI{
	meta:
		description = "Trojan:Win32/Emotet.EI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 59 5f 45 4d 4f 54 45 54 2e 31 } //1 BY_EMOTET.1
		$a_01_1 = {50 59 5f 45 4d 4f 54 45 54 } //1 PY_EMOTET
		$a_01_2 = {23 23 23 23 23 23 23 23 23 23 28 28 28 28 29 29 29 29 29 63 4f 64 65 2d 50 41 53 53 57 4f 52 44 21 21 21 2e 70 64 62 } //1 ##########(((()))))cOde-PASSWORD!!!.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_EI_2{
	meta:
		description = "Trojan:Win32/Emotet.EI,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 48 45 40 23 68 6a 65 72 68 45 57 48 5c 5c 65 68 72 65 5c 5c 65 68 23 48 45 4e 72 2e 70 64 62 } //1 WHE@#hjerhEWH\\ehre\\eh#HENr.pdb
		$a_01_1 = {6f 35 36 33 70 34 35 6d 36 70 33 35 76 38 34 30 36 38 33 34 35 76 36 33 38 34 35 36 76 38 33 30 34 35 70 36 2e 70 64 62 } //1 o563p45m6p35v84068345v638456v83045p6.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}