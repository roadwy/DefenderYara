
rule TrojanSpy_Win32_Nivdort_A{
	meta:
		description = "TrojanSpy:Win32/Nivdort.A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1e 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 55 fc c1 fa 04 33 d1 03 55 f8 89 55 f8 81 7d f0 90 01 02 00 00 75 13 90 00 } //0a 00 
		$a_03_1 = {89 4d e8 0f 10 90 01 02 b0 50 00 8b 55 e4 90 00 } //0a 00 
		$a_03_2 = {4f 00 83 c1 59 51 e8 90 01 03 00 83 c4 04 a3 90 00 } //01 00 
		$a_03_3 = {74 3a 8b 4d f0 8b 55 e4 8d 84 0a 90 01 04 33 45 f8 89 45 f8 8b 4d f4 0f be 11 8b 45 e8 0f be 08 33 ca 8b 55 e8 88 0a 90 00 } //00 00 
		$a_00_4 = {80 } //10 00 
	condition:
		any of ($a_*)
 
}