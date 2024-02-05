
rule TrojanDownloader_Win32_Cutwail_AV{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {3b f1 7e 1b 8a 81 90 01 04 84 c0 74 0c 3a c2 74 08 32 c2 90 00 } //01 00 
		$a_01_1 = {66 83 7e 06 00 0f b7 4e 14 } //02 00 
		$a_03_2 = {8a 47 01 47 84 c0 75 f8 8b 15 90 01 04 8b 0b a0 90 01 04 89 17 51 88 47 04 ff 15 90 01 04 8b 03 6a 00 6a 00 8d 54 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}