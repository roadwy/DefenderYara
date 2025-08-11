
rule Trojan_Win64_Sainbox_C{
	meta:
		description = "Trojan:Win64/Sainbox.C,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 00 5c 00 2e 00 5c 00 54 00 72 00 75 00 65 00 53 00 69 00 67 00 68 00 74 00 } //10 \\.\TrueSight
		$a_03_1 = {ba 44 e0 22 00 48 8b cb ?? e8 } //10
		$a_03_2 = {45 88 54 06 ff 90 0a 1a 00 83 fd 04 } //10
		$a_01_3 = {83 fd 0a e9 00 00 00 00 0f 8d 0d 00 00 00 83 ed 03 e9 00 00 00 00 } //1
		$a_01_4 = {83 fd 0a 0f 8d 0d 00 00 00 83 ed 03 e9 00 00 00 00 e9 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=31
 
}