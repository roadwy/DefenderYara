
rule Backdoor_Win64_MeterpreterReverseShell_A{
	meta:
		description = "Backdoor:Win64/MeterpreterReverseShell.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed } //1
		$a_01_1 = {3a 56 79 a7 ff d5 } //1
		$a_01_2 = {4c 77 26 07 ff d5 } //1
		$a_01_3 = {57 89 9f c6 ff d5 } //1
		$a_01_4 = {12 96 89 e2 ff d5 } //1
		$a_01_5 = {58 a4 53 e5 ff d5 } //1
		$a_01_6 = {2d 06 18 7b ff d5 } //1
		$a_01_7 = {75 46 9e 86 ff d5 } //1
		$a_01_8 = {eb 55 2e 3b ff d5 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}