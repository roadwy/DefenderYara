
rule TrojanDownloader_Win32_Cutwail_BA{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 38 4d 75 05 38 50 01 74 0d 83 c1 01 83 e8 01 83 f9 64 72 e6 } //01 00 
		$a_01_1 = {3b f8 7d 09 83 c7 01 80 3c 37 3b 75 ea } //01 00 
		$a_01_2 = {8a 14 02 32 14 31 02 d1 3b fd 88 14 31 72 cf } //01 00 
		$a_01_3 = {0f b7 46 14 33 db 66 39 5e 06 8d 44 30 18 76 } //01 00 
		$a_03_4 = {80 7d 00 4d 0f 85 90 01 04 80 7d 01 5a 90 00 } //01 00 
		$a_03_5 = {2b f1 8a 01 84 c0 74 13 3c 90 01 01 74 02 34 90 01 01 88 04 0e 90 00 } //01 00 
		$a_01_6 = {ff d3 81 7c 24 10 5a 5a 5a 5a 74 0d } //00 00 
	condition:
		any of ($a_*)
 
}