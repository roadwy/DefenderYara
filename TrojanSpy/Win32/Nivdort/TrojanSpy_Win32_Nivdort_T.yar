
rule TrojanSpy_Win32_Nivdort_T{
	meta:
		description = "TrojanSpy:Win32/Nivdort.T,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 11 8b 45 90 01 01 0f be 08 33 ca 8b 55 90 01 01 88 0a 90 00 } //01 00 
		$a_03_1 = {6a 34 68 30 90 01 01 44 00 e8 90 01 04 83 c4 08 90 00 } //01 00 
		$a_03_2 = {6a 44 68 d8 90 01 01 44 00 e8 90 01 04 83 c4 08 90 00 } //01 00 
		$a_03_3 = {6a 20 68 80 90 01 01 44 00 e8 90 01 04 83 c4 08 90 00 } //01 00 
		$a_03_4 = {6a 7e 68 c0 90 01 01 44 00 e8 90 01 04 83 c4 08 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 a0 
	condition:
		any of ($a_*)
 
}