
rule TrojanDownloader_Win32_VB_LK{
	meta:
		description = "TrojanDownloader:Win32/VB.LK,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_00_0 = {4e 7d 8f 5c 00 66 00 73 00 72 00 2e 00 76 00 62 00 70 } //10
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_02_2 = {2f 00 78 00 69 00 61 00 [0-04] 2e 00 65 00 78 00 65 00 } //1
		$a_00_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 64 00 61 00 74 00 65 00 } //1 cmd.exe /c date
		$a_00_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=13
 
}