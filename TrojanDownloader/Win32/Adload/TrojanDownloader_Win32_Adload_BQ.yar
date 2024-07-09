
rule TrojanDownloader_Win32_Adload_BQ{
	meta:
		description = "TrojanDownloader:Win32/Adload.BQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 50 fe 4c fe 48 fe 44 fe 40 fe 3c fe 38 fe 34 fe 30 fe 2c fe 28 fe 24 fe 20 fe 1c fe } //1
		$a_03_1 = {04 1a fd 04 58 ff 3a 44 ff ?? 00 04 b4 fd fb ef 34 ff 04 d4 fd fb ef 14 ff 60 fd c7 50 fe 10 f8 06 ?? 00 6b 1a fd 2f 50 fe 36 04 00 34 ff 14 ff 1c 27 05 00 27 f5 03 00 00 00 6c 58 ff 1b ?? 00 2a 46 34 ff 04 6c ff fb ef 14 ff 0a ?? 00 08 00 74 10 fd 36 04 00 34 ff 14 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Adload_BQ_2{
	meta:
		description = "TrojanDownloader:Win32/Adload.BQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 83 f9 2d 74 06 66 83 f9 2f 75 28 0f b7 48 02 66 83 f9 6f 74 17 66 83 f9 4f 74 11 66 83 f9 72 75 12 83 c0 04 } //1
		$a_03_1 = {66 8b 48 02 83 c0 02 66 85 c9 75 f4 8b 0d ?? ?? 40 00 8b 15 ?? ?? 40 00 89 08 8b 0d ?? ?? 40 00 89 50 04 8b 15 ?? ?? 40 00 89 48 08 89 50 0c } //1
		$a_01_2 = {25 00 73 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 25 00 64 00 2e 00 74 00 6d 00 70 00 } //1 %s\window%d.tmp
		$a_03_3 = {64 00 32 00 2e 00 78 00 69 00 61 00 7a 00 68 00 61 00 69 00 38 00 2e 00 6e 00 65 00 74 00 2f 00 3f 00 69 00 64 00 3d 00 ?? ?? ?? ?? ?? ?? ?? ?? 26 00 32 00 37 00 33 00 38 00 36 00 36 00 36 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}