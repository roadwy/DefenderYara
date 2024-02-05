
rule TrojanDownloader_Win32_Dadobra_BM{
	meta:
		description = "TrojanDownloader:Win32/Dadobra.BM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 45 52 52 41 2e 43 4f 4d 2e 42 52 4c 32 33 55 4f 4c 2e 43 4f 4d 2e 42 52 44 46 39 30 4e 41 4f 56 41 49 50 45 47 41 52 36 59 41 48 4f 4f 2e 43 4f 4d 2e } //01 00 
		$a_02_1 = {51 b9 09 00 00 00 6a 00 6a 00 49 75 f9 87 4d fc 53 56 57 89 4d f4 89 55 f8 89 45 fc 8b 45 fc e8 90 01 04 8b 45 f8 e8 90 01 04 33 c0 55 68 90 01 04 64 ff 30 64 89 20 83 7d f8 00 75 0d 8b 45 f4 e8 90 01 04 e9 e1 01 00 00 8d 45 e8 ba 90 01 04 e8 90 01 04 8d 45 ec e8 90 01 04 8b 45 e8 e8 90 01 04 89 45 f0 33 f6 90 00 } //01 00 
		$a_02_2 = {8b f8 8d 45 ec 50 89 7d d0 c6 45 d4 00 8d 55 d0 33 c9 b8 90 01 04 e8 90 01 04 8b 45 f8 e8 90 01 04 85 c0 0f 8e 59 01 00 00 89 45 dc c7 45 e4 01 00 00 00 a1 90 01 04 8b 00 e8 90 01 04 8b 45 f8 8b 55 e4 0f b6 44 10 ff 03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d 03 46 eb 05 be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 8d 55 d0 33 c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}