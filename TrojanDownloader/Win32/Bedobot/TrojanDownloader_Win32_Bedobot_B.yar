
rule TrojanDownloader_Win32_Bedobot_B{
	meta:
		description = "TrojanDownloader:Win32/Bedobot.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {46 8b 45 ec 80 3c 30 40 74 09 3b 77 38 0f 8e } //02 00 
		$a_01_1 = {8b 45 ec 80 3c 30 3e 74 09 3b 77 38 0f 8e } //02 00 
		$a_01_2 = {8d 44 24 01 50 68 b8 0b 00 00 8d 4c 24 08 33 d2 8b c6 e8 } //02 00 
		$a_01_3 = {89 45 ec 69 45 08 e8 03 00 00 89 45 f0 8d 45 ec 89 45 e8 eb 05 } //02 00 
		$a_01_4 = {8d 40 00 53 51 8b d8 c7 04 24 01 00 00 00 54 68 7e 66 04 80 8b 43 08 50 e8 } //00 00 
	condition:
		any of ($a_*)
 
}