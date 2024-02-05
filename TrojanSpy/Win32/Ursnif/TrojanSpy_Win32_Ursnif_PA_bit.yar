
rule TrojanSpy_Win32_Ursnif_PA_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.PA!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 5c 6d 61 69 6c 73 6c 6f 74 5c 73 6c 25 78 } //01 00 
		$a_03_1 = {70 6e 6c 73 ff d6 89 45 90 01 01 3b c7 0f 84 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_2 = {8b 43 3c 03 c3 0f b7 50 06 6b d2 28 56 0f b7 70 14 81 f1 3a 24 00 00 0f b7 c9 03 d0 } //01 00 
		$a_01_3 = {83 7d f8 00 75 62 0f ba 26 1d 73 16 0f ba 26 1f 0f 92 c0 0f b6 c0 f7 d8 1b c0 83 e0 20 83 c0 20 } //00 00 
	condition:
		any of ($a_*)
 
}