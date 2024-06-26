
rule TrojanDownloader_Win32_Banload_DD{
	meta:
		description = "TrojanDownloader:Win32/Banload.DD,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //05 00  SOFTWARE\Borland\Delphi
		$a_02_1 = {64 ff 30 64 89 20 6a 00 6a 00 8b 45 f8 e8 90 01 02 fb ff 50 8b 45 fc e8 90 01 02 fb ff 50 6a 00 e8 90 01 02 fd ff 90 00 } //05 00 
		$a_02_2 = {83 2d b8 fb 44 00 01 73 28 b8 90 01 01 c6 44 00 e8 90 01 01 75 fb ff e8 00 ff ff ff 68 90 01 01 c6 44 00 e8 90 01 01 9e fb ff a3 bc fb 44 00 b8 90 01 01 23 44 00 e8 90 01 01 69 fc ff c3 00 00 54 61 73 6b 62 61 72 43 72 65 61 74 65 64 00 90 00 } //01 00 
		$a_00_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_01_5 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //00 00  SetWindowsHookExA
	condition:
		any of ($a_*)
 
}