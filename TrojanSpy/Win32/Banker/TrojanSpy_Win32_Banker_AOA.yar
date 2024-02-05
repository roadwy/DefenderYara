
rule TrojanSpy_Win32_Banker_AOA{
	meta:
		description = "TrojanSpy:Win32/Banker.AOA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 47 62 50 6c 75 67 69 6e } //01 00 
		$a_01_1 = {5c 53 63 70 61 64 } //01 00 
		$a_01_2 = {42 72 61 64 69 6e 68 61 } //01 00 
		$a_01_3 = {4c 61 72 61 6e 6a 61 } //01 00 
		$a_03_4 = {ba 04 00 00 00 e8 90 01 04 a1 90 01 04 e8 90 01 04 8d 55 d0 b8 90 01 04 e8 90 01 04 8b 55 d0 b8 90 01 04 e8 90 01 04 8d 55 cc b8 90 01 04 e8 90 01 04 8b 55 cc b8 90 01 04 e8 90 01 04 8d 55 c8 b8 90 01 04 e8 90 01 04 8b 55 c8 8b c6 e8 90 01 04 0f b6 05 90 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 f0 
	condition:
		any of ($a_*)
 
}