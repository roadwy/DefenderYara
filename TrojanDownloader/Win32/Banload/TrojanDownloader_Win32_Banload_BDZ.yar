
rule TrojanDownloader_Win32_Banload_BDZ{
	meta:
		description = "TrojanDownloader:Win32/Banload.BDZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 17 32 55 10 88 17 81 fe 90 01 04 7d 90 01 01 be 90 01 04 40 49 75 90 00 } //01 00 
		$a_03_1 = {0f b7 5c 70 fe 33 5d 90 01 01 3b fb 7c 90 01 01 81 c3 ff 00 00 00 2b df eb 02 90 00 } //01 00 
		$a_03_2 = {0f b6 09 32 4d 10 8b 5d 08 03 da 88 0b 3b 45 90 01 01 7e 02 8b f0 3b f0 7d 03 89 75 90 01 01 42 ff 4d 90 01 01 75 da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}