
rule TrojanDownloader_Win32_SmallAgent_AM_MTB{
	meta:
		description = "TrojanDownloader:Win32/SmallAgent.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 46 04 80 f7 f7 8b 0e c0 e3 03 0a 5d 0c 80 cb c0 88 3c 01 8b 46 04 8b 0e 5f 88 5c 01 01 83 46 04 02 c7 46 08 } //01 00 
		$a_01_1 = {08 48 01 8b 4b 04 8b 03 80 4c 01 01 04 8b 4b 04 8b 03 80 4c 01 01 80 8b 4b 04 8b 03 80 4c 01 02 24 8b 4b 04 8b 03 41 89 4b 04 c7 44 01 02 00 00 00 00 8b cb 83 43 04 06 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_SmallAgent_AM_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/SmallAgent.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c7 85 b0 fe ff ff 2e 9a cb a7 c7 85 b4 fe ff ff d6 8e 07 4b c7 85 b8 fe ff ff d7 20 57 95 c7 85 bc fe ff ff 95 e0 47 fc c7 85 c0 fe ff ff a7 cf d2 ea c7 85 c4 fe ff ff 8a 11 05 18 c7 85 c8 fe ff ff 5e 6a 61 fe c7 85 cc fe ff ff eb 44 e7 ae c7 85 90 fd ff ff 67 f4 bf c2 } //0a 00 
		$a_01_1 = {c7 85 e0 fe ff ff 1e 26 16 9c c7 85 e4 fe ff ff 92 fe 4e ee c7 85 e8 fe ff ff 4d fd 0f d9 c7 85 ec fe ff ff e3 a9 d6 a7 c7 85 f0 fe ff ff 01 8c 4f 20 c7 85 f4 fe ff ff f4 24 d7 e3 c7 85 f8 fe ff ff c3 b6 96 d7 c7 85 fc fe ff ff 22 29 16 2d c7 85 00 ff ff ff 49 d2 6e fa c7 85 04 ff ff ff a2 4e 20 f8 c7 85 08 ff ff ff b5 eb 9e 84 } //0a 00 
		$a_01_2 = {c7 85 10 fe ff ff 73 e1 ae 60 c7 85 14 fe ff ff 23 8b 64 41 c7 85 18 fe ff ff 56 8d a8 88 c7 85 1c fe ff ff 84 94 70 80 c7 85 20 fe ff ff dd 03 b6 19 c7 85 24 fe ff ff 3a aa 9f 4d c7 85 28 fe ff ff ce 7a c8 9e c7 85 2c fe ff ff 23 31 01 2d c7 85 f0 fc ff ff 3b 95 da 10 } //05 00 
		$a_01_3 = {c7 85 70 ff ff ff 01 60 f8 90 c7 85 74 ff ff ff 67 b7 23 9d c7 85 78 ff ff ff 86 34 40 4a c7 85 7c ff ff ff 52 16 17 96 c7 85 60 ff ff ff 49 25 b9 d4 c7 85 64 ff ff ff 67 b7 23 9d } //05 00 
		$a_01_4 = {8b 45 e8 8a 08 88 4d f2 83 45 e8 01 80 7d f2 00 } //0a 00 
		$a_01_5 = {c7 85 f0 fd ff ff 1c 5e 45 ee c7 85 f4 fd ff ff 6f 5b 1d 00 c7 85 f8 fd ff ff 55 8c 5f e1 c7 85 fc fd ff ff 61 13 fd 2d c7 85 00 fe ff ff c3 3d ea a9 c7 85 04 fe ff ff 73 a4 6b 5d c7 85 08 fe ff ff 68 85 87 4e c7 85 0c fe ff ff c2 99 4b db } //0a 00 
		$a_01_6 = {c7 45 fc 00 10 03 00 c7 45 f8 90 0a 00 00 c7 45 f4 00 ec 00 00 c7 45 ec fe 00 28 12 c7 45 f0 62 b9 8f 6c c7 45 e4 e5 c0 0f 6d c7 45 e8 a0 95 bb 2c c7 45 dc 5c b2 b2 98 c7 45 e0 5f 11 99 18 } //0a 00 
		$a_01_7 = {c7 84 24 a0 02 00 00 cf 8e 1c fc c7 84 24 a4 02 00 00 52 fe 34 e8 c7 84 24 a8 02 00 00 d0 72 4b 15 c7 84 24 ac 02 00 00 33 f7 e3 36 c7 84 24 b0 02 00 00 a9 09 61 58 c7 84 24 b4 02 00 00 34 c7 6d e5 c7 84 24 b8 02 00 00 5a 9a 65 bc c7 84 24 bc 02 00 00 0d 6c 9a e7 } //00 00 
	condition:
		any of ($a_*)
 
}