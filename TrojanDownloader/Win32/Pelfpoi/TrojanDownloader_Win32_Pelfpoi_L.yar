
rule TrojanDownloader_Win32_Pelfpoi_L{
	meta:
		description = "TrojanDownloader:Win32/Pelfpoi.L,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 7b 30 30 30 32 31 34 41 30 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d 5d } //1 [{000214A0-0000-0000-C000-000000000046}]
		$a_01_1 = {61 74 62 66 73 68 2e 65 78 65 } //1 atbfsh.exe
		$a_03_2 = {f7 ff eb 0d ba 01 00 00 00 8b 45 f4 e8 ?? ?? 00 00 47 4e 0f 85 ?? ?? ff ff 8b 45 ?? e8 ?? ?? ff ff e8 ?? ?? 00 00 } //2
		$a_03_3 = {b2 01 a1 b8 d3 48 00 e8 ?? ?? fd ff 89 45 fc 8b 45 fc e8 ?? ?? fd ff 83 c0 70 ba ?? ?? 4b 00 e8 ?? ?? f4 ff b2 01 a1 b8 77 41 00 e8 ?? ?? f4 ff } //2
		$a_03_4 = {8d 45 fc 50 8d 55 e8 8b 43 30 e8 ?? ?? ff ff 8b 45 e8 89 45 ec c6 45 f0 0b 8d 55 e4 8b 43 30 e8 ?? ?? ff ff 8b 45 e4 89 45 f4 c6 45 f8 0b 8d 45 ec 50 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_03_4  & 1)*2) >=6
 
}