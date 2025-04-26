
rule TrojanDownloader_Win32_Banload_BH{
	meta:
		description = "TrojanDownloader:Win32/Banload.BH,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_00_0 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_2 = {33 c0 55 68 64 7e 40 00 64 ff 30 64 89 20 68 74 7e 40 00 6a 00 e8 10 ff ff ff 68 e8 03 00 00 e8 2a f9 ff ff b8 } //1
		$a_02_3 = {ff ff 4b 75 e3 6a 00 6a 00 68 ?? ?? 40 00 68 ?? ?? 40 00 6a 00 e8 b2 fe ff ff 6a 05 68 ?? ?? 40 00 e8 f2 c6 ff ff 33 c0 5a 59 59 64 89 10 68 } //10
		$a_02_4 = {40 00 64 ff 30 64 89 20 b8 ?? ?? 40 00 ?? ?? ?? 40 00 e8 ?? ?? ff ff 68 fe 00 00 00 68 ?? ?? 40 00 e8 ?? ?? ff ff 8d } //1
		$a_00_5 = {ff ff 50 6a 00 e8 f6 c6 ff ff 6a 05 8d 45 dc 8b 0d c0 a8 40 00 8b 15 ac a8 40 00 e8 f8 b8 ff ff 53 e8 fa c5 ff ff 33 c0 5a 59 59 64 89 10 68 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*10+(#a_02_4  & 1)*1+(#a_00_5  & 1)*10) >=13
 
}