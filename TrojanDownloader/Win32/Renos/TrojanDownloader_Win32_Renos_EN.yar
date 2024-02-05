
rule TrojanDownloader_Win32_Renos_EN{
	meta:
		description = "TrojanDownloader:Win32/Renos.EN,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_03_0 = {8b f0 2b f2 8d 9b 00 00 00 00 8a 0a 80 f1 90 01 01 88 0c 16 74 08 8a 4a 01 42 84 c9 75 ee 90 00 } //02 00 
		$a_01_1 = {75 1a 83 c3 07 83 ee 07 83 c7 07 83 fb 46 72 c2 } //02 00 
		$a_01_2 = {33 c0 50 0f 01 4c 24 fe 58 c3 } //01 00 
		$a_00_3 = {c7 46 0c 76 54 32 10 } //01 00 
		$a_03_4 = {c7 06 01 23 45 67 0f bf 90 01 04 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}