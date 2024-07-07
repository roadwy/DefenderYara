
rule Backdoor_Win32_Eayla_A{
	meta:
		description = "Backdoor:Win32/Eayla.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6e 61 76 65 72 20 76 73 20 61 6c 79 61 65 2c 44 65 66 65 61 74 65 64 20 70 69 6c 6c 73 00 } //1
		$a_01_1 = {73 68 69 74 20 69 73 20 61 6c 79 61 65 00 } //1
		$a_01_2 = {c6 45 ec 4e c6 45 ed 56 c6 45 ee 43 c6 45 ef 41 c6 45 f0 67 c6 45 f1 65 c6 45 f2 6e c6 45 f3 74 c6 45 f4 2e c6 45 f5 6e c6 45 f6 70 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}