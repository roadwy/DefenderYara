
rule TrojanSpy_Win32_Nivdort_gen_E{
	meta:
		description = "TrojanSpy:Win32/Nivdort.gen!E,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 ea 01 89 55 90 02 10 81 7d 90 01 01 2c 01 00 00 75 90 00 } //01 00 
		$a_03_1 = {83 c0 59 50 6a 00 8b 90 02 0a e8 90 01 03 00 83 c4 0c 90 00 } //01 00 
		$a_01_2 = {8b 45 e8 0f be 08 33 ca 8b 55 e8 88 0a 8b 45 f8 83 c0 01 89 45 f8 } //01 00 
		$a_03_3 = {83 c4 04 8b 4d f8 c1 e1 90 01 01 8b 55 f8 2b d1 8b 45 fc c1 f8 90 01 01 03 d0 90 00 } //01 00 
		$a_03_4 = {8b 4d 08 89 04 8d 90 01 02 51 00 8b 55 e4 c1 fa 06 69 d2 90 00 } //00 00 
		$a_00_5 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}