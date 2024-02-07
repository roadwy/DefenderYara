
rule TrojanDownloader_Win32_Small_DBA{
	meta:
		description = "TrojanDownloader:Win32/Small.DBA,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_02_2 = {63 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 20 68 74 74 70 3a 2f 2f 90 02 40 2f 66 6f 74 6f 73 2e 68 74 6d 90 00 } //01 00 
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 20 2f 73 77 66 2f 64 6f 77 6e 2f 69 67 73 67 61 74 65 73 2e 65 78 65 90 00 } //01 00 
		$a_00_4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 61 74 68 79 78 6c 6e 76 78 2e 65 78 65 } //00 00  C:\WINDOWS\athyxlnvx.exe
	condition:
		any of ($a_*)
 
}