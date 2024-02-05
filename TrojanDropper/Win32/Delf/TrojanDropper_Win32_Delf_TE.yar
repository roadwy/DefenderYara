
rule TrojanDropper_Win32_Delf_TE{
	meta:
		description = "TrojanDropper:Win32/Delf.TE,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {b2 08 b0 04 e8 90 01 02 ff ff 8d 4d 90 01 01 b2 03 b0 02 e8 90 01 02 ff ff 8d 4d 90 01 01 b2 02 b0 01 e8 90 00 } //0a 00 
		$a_01_1 = {6a 0a 6a 00 e8 } //0a 00 
		$a_01_2 = {45 6e 75 6d 52 65 73 6f 75 72 63 65 4e 61 6d 65 73 41 00 } //01 00 
		$a_03_3 = {80 7d ff 00 74 4f 0f b6 75 ff 85 f6 7e 47 b8 13 00 00 00 e8 90 01 03 ff 8a 90 90 90 01 03 00 8d 45 f4 90 00 } //01 00 
		$a_03_4 = {74 51 0f b6 75 fb 85 f6 7e 49 b8 13 00 00 00 e8 90 01 03 ff 0f b6 90 90 90 01 03 00 8d 45 f4 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}