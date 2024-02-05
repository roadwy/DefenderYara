
rule TrojanDropper_Win32_Delf_DV{
	meta:
		description = "TrojanDropper:Win32/Delf.DV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 7d fe ff ff a1 90 01 04 50 e8 90 01 02 ff ff b8 83 01 00 00 e8 90 00 } //01 00 
		$a_01_1 = {83 fa 04 7c 0d 8b 18 0f b6 1c 13 33 d9 8b 38 88 1c 17 42 4e 75 ea } //01 00 
		$a_01_2 = {75 0b 8b 43 34 03 43 28 89 45 c0 eb 06 03 43 28 89 45 c0 8d 85 10 ff ff ff } //01 00 
		$a_01_3 = {2d 66 75 63 6b 20 22 00 } //00 00 
	condition:
		any of ($a_*)
 
}