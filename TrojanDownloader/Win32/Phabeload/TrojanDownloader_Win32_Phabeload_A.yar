
rule TrojanDownloader_Win32_Phabeload_A{
	meta:
		description = "TrojanDownloader:Win32/Phabeload.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 08 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 0f b7 00 85 c0 75 04 33 c0 eb 28 8b 45 fc 2d 90 01 02 40 00 d1 e8 8b 4d f8 8b 55 08 66 8b 04 45 90 01 02 40 00 66 89 04 4a 8b 45 f8 40 89 45 f8 eb 90 00 } //08 00 
		$a_03_1 = {8b 45 fc 8b 4d 08 66 8b 14 41 b9 90 01 02 40 00 e8 90 01 04 89 45 f8 83 7d f8 00 75 04 33 c0 eb 21 8b 45 f8 2d 90 01 02 40 00 d1 e8 8b 4d fc 8b 55 08 66 8b 04 45 c8 34 40 00 66 89 04 4a eb 90 00 } //01 00 
		$a_03_2 = {b9 00 01 80 00 b8 90 01 04 0f 45 c1 50 53 53 53 ff 75 90 01 01 68 90 01 04 ff 75 90 01 01 ff 15 90 01 04 89 45 f4 85 c0 0f 84 90 01 04 38 5d ff 74 16 6a 04 8d 4d 90 01 01 c7 45 90 01 01 00 33 00 00 51 6a 1f 50 ff 15 90 00 } //01 00 
		$a_03_3 = {ba 00 01 80 00 b8 90 01 04 0f 45 c2 50 53 53 53 ff 75 90 01 01 68 90 01 04 51 ff 15 90 01 04 8b f0 85 f6 0f 84 90 01 04 38 5d ff 74 16 6a 04 8d 45 90 01 01 c7 45 90 01 01 00 33 00 00 50 6a 1f 56 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}