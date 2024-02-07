
rule TrojanDownloader_Win32_Banload_AV{
	meta:
		description = "TrojanDownloader:Win32/Banload.AV,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 74 6f 46 69 6c 65 41 } //0a 00  URLDownloadtoFileA
		$a_00_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //0a 00  ShellExecuteA
		$a_02_3 = {80 e3 0f b8 90 01 04 0f b6 44 30 ff 24 0f 32 d8 80 f3 0a 8d 45 fc e8 90 01 04 8b 55 fc 90 00 } //0a 00 
		$a_00_4 = {8b 55 fc 0f b6 54 3a ff 80 e2 f0 02 d3 88 54 38 ff 46 83 fe 0d 7e 05 be 01 00 00 00 47 ff 4d f4 75 ba } //00 00 
	condition:
		any of ($a_*)
 
}