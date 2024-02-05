
rule TrojanDownloader_Win32_Cutwail_AO{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 1b 81 f3 90 01 04 81 fb 90 01 04 75 09 8b 1d 90 01 04 c6 03 8b 90 00 } //01 00 
		$a_03_1 = {53 83 29 05 50 6a 00 6a 00 ff 11 6a ff 50 ff 15 90 01 04 ff 24 24 90 00 } //01 00 
		$a_01_2 = {8b 54 24 08 66 33 d2 33 c0 8b ff 66 b8 01 10 66 48 66 81 3a 4d 5a 74 04 2b d0 eb f5 } //01 00 
		$a_01_3 = {05 e9 00 00 00 50 8b 45 e4 29 04 24 8f 45 f8 8d 45 fc 50 6a 04 ff 75 f4 ff 75 f8 } //00 00 
	condition:
		any of ($a_*)
 
}