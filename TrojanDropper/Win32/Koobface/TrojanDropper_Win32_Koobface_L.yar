
rule TrojanDropper_Win32_Koobface_L{
	meta:
		description = "TrojanDropper:Win32/Koobface.L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 4d fc ff e8 24 00 00 00 83 7d e0 00 75 13 ff 75 08 6a 00 ff 35 90 01 02 44 00 ff 15 64 90 01 01 41 00 8b f0 8b c6 90 00 } //01 00 
		$a_03_1 = {ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 90 01 04 8b f0 90 00 } //01 00 
		$a_03_2 = {6a 1c 8d 45 d8 50 56 ff 15 1c 90 01 01 41 00 85 c0 74 77 8b 5d dc 8d 45 b4 50 ff 15 5c 90 01 01 41 00 8b 4d b8 a1 90 00 } //01 00 
		$a_03_3 = {41 00 ff 25 68 90 01 01 41 00 ff 25 6c 90 01 01 41 00 ff 25 70 90 01 01 41 00 ff 25 74 90 01 01 41 00 ff 25 78 90 01 01 41 00 ff 25 7c 90 01 01 41 00 ff 25 80 90 01 01 41 00 ff 25 84 90 01 01 41 00 cc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}