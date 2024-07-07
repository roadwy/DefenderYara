
rule TrojanDownloader_Win32_Banload_EX{
	meta:
		description = "TrojanDownloader:Win32/Banload.EX,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 45 78 65 63 } //1 WinExec
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_3 = {50 6a ec a1 8c 60 45 00 53 e8 cd 21 fb ff ba c4 46 45 00 b8 e0 46 45 00 e8 f2 fe ff ff 84 c0 74 0c 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}