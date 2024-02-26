
rule TrojanDownloader_Win32_GhostRAT_D_MTB{
	meta:
		description = "TrojanDownloader:Win32/GhostRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 4c 24 60 8b c7 0f 43 4c 24 60 99 f7 7c 24 90 01 01 8a 04 0a 8b 4c 24 90 01 01 30 04 0f 47 3b fe 90 00 } //02 00 
		$a_01_1 = {8b f8 ff d6 6a 01 ff d6 6a 01 ff d6 6a 01 ff d6 6a 01 ff d6 6a 01 ff d6 } //02 00 
		$a_03_2 = {0f be 00 8b 4d 90 01 01 8b 55 f8 0f b6 1c 11 31 c3 88 1c 11 8b 45 90 00 } //02 00 
		$a_01_3 = {ff d7 83 ec 04 c7 04 24 01 00 00 00 ff d7 83 ec 04 c7 04 24 01 00 00 00 ff d7 83 ec 04 c7 04 24 01 00 00 00 ff d7 83 ec 04 c7 04 24 01 00 00 00 ff d7 83 ec 04 c7 04 24 01 00 00 00 ff d7 } //00 00 
	condition:
		any of ($a_*)
 
}