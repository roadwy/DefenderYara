
rule TrojanDownloader_Win32_Tiny_GV{
	meta:
		description = "TrojanDownloader:Win32/Tiny.GV,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 45 43 20 44 6f 77 6e 6c 6f 61 64 65 72 } //01 00  SEC Downloader
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_00_2 = {2f 63 20 64 65 6c } //05 00  /c del
		$a_02_3 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 90 01 05 6a 00 ff 15 90 01 01 12 14 13 c7 05 90 01 01 15 14 13 07 00 01 00 68 90 01 01 15 14 13 ff 35 90 01 01 15 14 13 ff 15 90 01 01 12 14 13 a1 90 01 02 14 13 a3 90 01 01 13 14 13 6a 00 68 90 01 01 01 00 00 68 90 01 01 11 14 13 ff 35 90 01 01 13 14 13 ff 35 90 01 01 15 14 13 ff 15 90 01 01 12 14 13 8b 35 90 01 01 13 14 13 ff 35 90 01 01 15 14 13 ff 15 90 01 01 12 14 13 ff 35 90 01 01 15 14 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}