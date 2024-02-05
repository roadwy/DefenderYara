
rule TrojanDropper_Win32_Prefsap{
	meta:
		description = "TrojanDropper:Win32/Prefsap,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 45 08 83 e8 0c c7 40 04 32 72 65 73 c7 00 78 70 73 70 c7 05 90 01 04 01 00 00 00 e9 90 00 } //01 00 
		$a_03_1 = {03 45 08 83 e8 08 8b 08 81 f9 70 61 70 69 0f 85 90 01 01 00 00 00 68 c4 09 00 00 e8 90 00 } //01 00 
		$a_01_2 = {8a 55 10 8a 38 c0 c2 03 32 fa c0 cf 04 32 f9 88 38 40 41 3b 4d 0c 72 eb } //00 00 
	condition:
		any of ($a_*)
 
}