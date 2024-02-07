
rule TrojanDownloader_Win32_Delf_DP{
	meta:
		description = "TrojanDownloader:Win32/Delf.DP,SIGNATURE_TYPE_PEHSTR,13 00 13 00 0a 00 00 06 00 "
		
	strings :
		$a_01_0 = {62 61 6b 5c 68 6a 6f 62 31 32 33 5c 63 6f 6d } //06 00  bak\hjob123\com
		$a_01_1 = {2e 72 72 61 64 73 2e 63 6e 2f 69 6e 73 2f } //06 00  .rrads.cn/ins/
		$a_01_2 = {24 24 33 30 36 38 39 2e 62 61 74 } //04 00  $$30689.bat
		$a_01_3 = {6d 73 67 65 72 } //04 00  msger
		$a_01_4 = {47 65 74 64 4e 65 77 2e 65 78 65 } //02 00  GetdNew.exe
		$a_01_5 = {64 65 6c 20 } //02 00  del 
		$a_01_6 = {69 66 20 65 78 69 73 74 } //02 00  if exist
		$a_01_7 = {64 65 6c 20 2f 71 20 2f 66 } //02 00  del /q /f
		$a_01_8 = {25 73 22 20 2d 70 22 25 73 22 20 2d 6f 2d 20 2d 73 20 2d 64 22 25 73 } //01 00  %s" -p"%s" -o- -s -d"%s
		$a_01_9 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}