
rule TrojanDownloader_Win32_Banload_DX{
	meta:
		description = "TrojanDownloader:Win32/Banload.DX,SIGNATURE_TYPE_PEHSTR_EXT,2b 00 2b 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //30 SOFTWARE\Borland\Delphi\RTL
		$a_02_1 = {e8 d2 6f fb ff 5f 5e 5b 5d c3 00 70 6c 75 67 69 6e 00 00 5c 61 2e 65 78 65 00 00 68 74 74 70 3a 2f 2f [0-40] 2e 65 78 65 } //10
		$a_01_2 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //1 SetWindowsHookExA
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_00_4 = {57 69 6e 45 78 65 63 } //1 WinExec
	condition:
		((#a_00_0  & 1)*30+(#a_02_1  & 1)*10+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=43
 
}