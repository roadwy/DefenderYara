
rule TrojanDownloader_Win32_Rugmi_HNS_MTB{
	meta:
		description = "TrojanDownloader:Win32/Rugmi.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 42 3c 0f be 0b 8b 7c 10 2c 8d 44 24 10 8b 6c 0b 04 8d 71 0c 50 6a 40 03 f3 03 fa 8b 5c 0b 08 53 57 c7 44 24 20 00 00 00 00 } //0a 00 
		$a_03_1 = {53 ff 54 24 2c 8b 0d 90 01 04 8b 44 24 04 8d 90 01 01 08 8b 90 01 01 04 8d 90 01 01 08 89 90 01 01 24 8d 90 01 01 08 f7 d8 03 90 01 01 3d f8 90 01 01 00 00 7d 0d f7 d8 3d f8 90 01 01 00 00 90 00 } //0a 00 
		$a_01_2 = {89 45 ec 8b 45 fc 8b 40 5c 89 45 f0 83 65 e8 00 8b 45 f0 83 38 00 74 3f ff 75 ec } //0a 00 
		$a_01_3 = {00 83 ec 10 03 43 0c 01 d8 01 d3 89 1c 24 ff d0 c7 04 24 00 00 00 00 ff } //0a 00 
		$a_03_4 = {6a 04 58 6b c0 00 8b 4d f0 8b 55 e8 3b 14 01 74 90 01 01 6a 04 58 c1 e0 00 8b 4d f0 8b 55 e8 3b 14 01 74 08 6a 00 90 00 } //0a 00 
		$a_03_5 = {89 c1 41 8b 44 0e 04 4c 01 f1 48 83 c1 08 ba 04 00 00 00 8b 74 11 fc 01 c6 89 74 17 04 48 83 c2 04 48 81 fa 90 01 02 00 00 72 90 01 01 8b 05 90 01 04 89 47 08 90 00 } //05 00 
		$a_03_6 = {8b 4f 0c 03 c8 a1 90 01 04 03 cf 03 f8 57 ff d1 83 c4 04 6a 00 ff 90 00 } //05 00 
		$a_01_7 = {8b 5e 04 2b f7 8b 04 0e 8d 49 04 03 c3 89 41 fc 83 ea 01 75 f0 } //00 00 
	condition:
		any of ($a_*)
 
}