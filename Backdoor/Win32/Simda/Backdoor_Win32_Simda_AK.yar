
rule Backdoor_Win32_Simda_AK{
	meta:
		description = "Backdoor:Win32/Simda.AK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {21 58 8a c3 30 90 a4 ef bc c5 c3 56 a8 3f c5 63 } //01 00 
		$a_01_1 = {44 09 97 10 a0 ee cc 2e c6 06 c0 f9 48 25 1c 3c } //01 00 
		$a_01_2 = {fb 6e d1 03 57 4d 17 7c b4 0a 1c 7e 81 f3 a0 a5 } //01 00 
		$a_01_3 = {d6 e5 46 36 5c 5a d1 03 06 e7 8d b2 0a 35 32 } //01 00 
		$a_01_4 = {69 44 de e3 ad c5 6d 19 9a 6c ee 50 b5 43 } //01 00 
		$a_01_5 = {93 da a9 87 96 48 8c 45 17 86 c1 09 fc 3a 10 } //01 00 
		$a_01_6 = {db 77 3f dc 11 4e 71 e7 f9 6b ac 2c f9 f4 16 71 13 80 10 60 25 2e 2c ea 09 ff a5 bb b0 93 0a 10 } //00 00 
	condition:
		any of ($a_*)
 
}