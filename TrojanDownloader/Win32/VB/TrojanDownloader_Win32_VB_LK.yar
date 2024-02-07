
rule TrojanDownloader_Win32_VB_LK{
	meta:
		description = "TrojanDownloader:Win32/VB.LK,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4e 7d 8f 5c 00 66 00 73 00 72 00 2e 00 76 00 62 00 70 } //01 00 
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_02_2 = {2f 00 78 00 69 00 61 00 90 02 04 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_00_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 64 00 61 00 74 00 65 00 } //01 00  cmd.exe /c date
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}