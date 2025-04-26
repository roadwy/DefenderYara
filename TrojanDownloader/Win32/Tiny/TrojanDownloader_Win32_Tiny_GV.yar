
rule TrojanDownloader_Win32_Tiny_GV{
	meta:
		description = "TrojanDownloader:Win32/Tiny.GV,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 45 43 20 44 6f 77 6e 6c 6f 61 64 65 72 } //1 SEC Downloader
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_2 = {2f 63 20 64 65 6c } //1 /c del
		$a_02_3 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 ?? ?? ?? ?? ?? 6a 00 ff 15 ?? 12 14 13 c7 05 ?? 15 14 13 07 00 01 00 68 ?? 15 14 13 ff 35 ?? 15 14 13 ff 15 ?? 12 14 13 a1 ?? ?? 14 13 a3 ?? 13 14 13 6a 00 68 ?? 01 00 00 68 ?? 11 14 13 ff 35 ?? 13 14 13 ff 35 ?? 15 14 13 ff 15 ?? 12 14 13 8b 35 ?? 13 14 13 ff 35 ?? 15 14 13 ff 15 ?? 12 14 13 ff 35 ?? 15 14 13 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*5) >=8
 
}