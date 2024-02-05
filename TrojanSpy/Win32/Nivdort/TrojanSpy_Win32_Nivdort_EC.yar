
rule TrojanSpy_Win32_Nivdort_EC{
	meta:
		description = "TrojanSpy:Win32/Nivdort.EC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 8b 4c 24 90 02 0a 0f b6 31 31 c6 89 f0 88 c2 88 11 90 00 } //01 00 
		$a_01_1 = {89 e1 c7 01 e5 08 00 00 ff d0 83 ec 04 } //01 00 
		$a_01_2 = {89 e1 c7 01 f4 01 00 00 ff d0 83 ec 04 } //01 00 
		$a_03_3 = {89 e2 c7 02 c3 62 01 00 89 44 24 90 01 01 ff d1 83 ec 04 90 00 } //01 00 
		$a_01_4 = {89 e1 c7 01 1f 04 00 00 ff d0 83 ec 04 } //00 00 
		$a_00_5 = {e7 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}