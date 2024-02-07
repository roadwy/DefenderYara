
rule TrojanDownloader_Win32_Secdow_A{
	meta:
		description = "TrojanDownloader:Win32/Secdow.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 45 43 20 44 6f 77 6e 6c 6f 61 64 65 72 } //02 00  SEC Downloader
		$a_00_1 = {73 76 63 68 6f 73 74 2e 65 78 65 } //02 00  svchost.exe
		$a_00_2 = {63 3a 5c 73 65 63 2e 65 78 65 } //02 00  c:\sec.exe
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //02 00  URLDownloadToFileA
		$a_00_4 = {76 69 72 75 73 2e 73 63 72 } //02 00  virus.scr
		$a_00_5 = {63 3a 5c 76 69 72 75 73 2e 65 78 65 } //05 00  c:\virus.exe
		$a_03_6 = {6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 68 90 01 04 6a 00 ff 15 90 01 04 c7 05 90 01 08 68 90 01 04 ff 35 90 01 04 ff 15 90 01 04 a1 90 01 04 a3 90 01 04 6a 00 68 90 01 03 00 68 90 01 04 ff 35 90 01 04 ff 35 90 01 04 ff 15 90 01 04 8b 35 90 01 04 ff 35 90 01 04 ff 15 90 01 04 ff 35 90 01 04 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}