
rule TrojanDownloader_Win32_Banload_ZED{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZED,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {75 05 83 fb 03 7e de 90 09 1b 00 8d 55 90 01 01 b8 90 01 04 e8 90 01 02 ff ff 8b 45 90 01 01 8b 55 90 01 01 e8 90 01 02 ff ff 43 84 c0 90 00 } //01 00 
		$a_03_1 = {7e 2f bf 01 00 00 00 8b c3 34 01 84 c0 74 1b 8d 45 f0 8b 55 fc 0f b6 54 3a ff e8 90 01 02 fe ff 8b 55 f0 8d 45 f8 e8 90 01 02 fe ff 80 f3 01 47 4e 75 d6 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}