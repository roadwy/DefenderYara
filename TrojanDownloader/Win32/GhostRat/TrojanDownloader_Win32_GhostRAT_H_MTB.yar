
rule TrojanDownloader_Win32_GhostRAT_H_MTB{
	meta:
		description = "TrojanDownloader:Win32/GhostRAT.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 28 8b f8 51 66 c7 44 24 14 02 00 ff 15 90 01 02 41 00 66 89 44 24 12 8b 90 01 01 0c 6a 10 8b 02 8d 54 24 14 52 8b 08 8b 46 08 50 89 4c 24 20 ff 15 90 00 } //02 00 
		$a_03_1 = {53 8b f8 66 c7 44 24 14 02 00 ff 90 01 02 78 41 00 66 89 44 24 12 8b 90 01 01 0c 6a 10 8b 08 8d 44 24 14 50 8b 11 8b 4e 08 51 89 54 24 20 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}