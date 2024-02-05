
rule TrojanDropper_Win32_Beastdoor_DV{
	meta:
		description = "TrojanDropper:Win32/Beastdoor.DV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 10 01 00 00 68 90 01 02 40 00 a1 90 01 02 40 00 50 ff 15 90 01 02 40 00 ba 05 01 00 00 b8 90 01 02 40 00 8a 08 32 0b 88 08 40 4a 75 f6 33 c0 8a 03 31 05 90 01 02 40 00 31 05 90 01 02 40 00 5b 90 00 } //01 00 
		$a_01_1 = {8b 55 f8 85 d2 72 11 42 33 c0 33 c9 8a 0c 03 33 ce 88 0c 03 40 4a 75 f2 46 81 fe c9 00 00 00 75 df 8b 55 f8 85 d2 72 13 42 33 c0 8a 0c 03 } //01 00 
		$a_03_2 = {40 00 33 c0 a0 90 01 02 40 00 31 05 90 01 02 40 00 e8 90 01 02 ff ff 8d 45 c4 ba 90 01 02 40 00 b9 05 01 00 00 e8 90 01 02 ff ff 8b 45 c4 8b 0d 90 01 02 40 00 8b 15 90 01 02 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}