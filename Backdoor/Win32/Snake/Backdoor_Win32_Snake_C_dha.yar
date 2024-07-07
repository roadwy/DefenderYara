
rule Backdoor_Win32_Snake_C_dha{
	meta:
		description = "Backdoor:Win32/Snake.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 01 8a 04 38 32 06 88 45 13 8d 45 13 50 56 e8 } //1
		$a_01_1 = {31 64 4d 33 75 75 34 6a 37 46 77 34 73 6a 6e 62 } //1 1dM3uu4j7Fw4sjnb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}