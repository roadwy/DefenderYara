
rule TrojanDownloader_Win32_Bedobot_A{
	meta:
		description = "TrojanDownloader:Win32/Bedobot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 8b 45 ec 80 3c 30 40 74 09 3b 77 38 0f 8e } //01 00 
		$a_01_1 = {89 45 ec 69 45 08 e8 03 00 00 89 45 f0 8d 45 ec 89 45 e8 eb 05 } //01 00 
		$a_01_2 = {0f b7 4d fe c1 e9 08 32 0e 88 08 02 4d fe 0f b6 c9 66 0f af 4d fa 66 03 4d fc 66 89 4d fe } //01 00 
		$a_01_3 = {0f b7 4d fe c1 e9 08 32 0e 88 08 02 4d fe 0f b6 c9 66 0f af 4d fa 66 03 4d fc 66 89 4d fe 46 40 4a 75 dd b0 01 } //01 00 
		$a_03_4 = {e8 00 00 00 00 5f 81 ef 90 01 02 49 00 8b c7 81 c7 90 01 02 49 00 3b 47 2c 75 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}