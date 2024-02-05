
rule TrojanDownloader_Win32_Banload_EW{
	meta:
		description = "TrojanDownloader:Win32/Banload.EW,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //0a 00 
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00 
		$a_02_2 = {33 d2 a1 d4 0b 45 00 e8 e4 7d ff ff 33 d2 b8 90 01 04 e8 5c ff ff ff ba 90 01 04 b8 90 01 04 e8 ad fe ff ff 84 c0 74 0c 33 d2 b8 90 01 04 e8 3d ff ff ff 90 00 } //0a 00 
		$a_01_3 = {81 c4 f4 f7 ff ff 89 55 f8 89 45 fc 8b 45 fc e8 15 67 fb ff 8b 45 f8 e8 0d 67 fb ff 33 c0 55 68 13 dc 44 00 64 ff 30 64 89 20 8d 85 f7 fb ff ff 8b 55 fc e8 f1 a5 fb ff 8d 85 f6 f7 ff ff 8b 55 f8 e8 e3 a5 fb ff 6a 00 6a 00 8d 85 f6 f7 ff ff 50 8d 85 f7 fb ff ff 50 6a } //01 00 
		$a_01_4 = {00 6a 00 e8 b0 66 fd ff 33 c0 5a 59 59 64 89 10 68 1a dc 44 00 8d 45 f8 ba 02 00 00 00 e8 22 62 fb ff c3 e9 fc 5b fb ff eb eb 8b e5 5d c3 8b c0 33 d2 a1 d4 0b 45 00 e8 } //0a 00 
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00 
	condition:
		any of ($a_*)
 
}