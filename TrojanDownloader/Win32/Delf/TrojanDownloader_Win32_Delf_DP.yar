
rule TrojanDownloader_Win32_Delf_DP{
	meta:
		description = "TrojanDownloader:Win32/Delf.DP,SIGNATURE_TYPE_PEHSTR,13 00 13 00 0a 00 00 "
		
	strings :
		$a_01_0 = {62 61 6b 5c 68 6a 6f 62 31 32 33 5c 63 6f 6d } //6 bak\hjob123\com
		$a_01_1 = {2e 72 72 61 64 73 2e 63 6e 2f 69 6e 73 2f } //6 .rrads.cn/ins/
		$a_01_2 = {24 24 33 30 36 38 39 2e 62 61 74 } //6 $$30689.bat
		$a_01_3 = {6d 73 67 65 72 } //4 msger
		$a_01_4 = {47 65 74 64 4e 65 77 2e 65 78 65 } //4 GetdNew.exe
		$a_01_5 = {64 65 6c 20 } //2 del 
		$a_01_6 = {69 66 20 65 78 69 73 74 } //2 if exist
		$a_01_7 = {64 65 6c 20 2f 71 20 2f 66 } //2 del /q /f
		$a_01_8 = {25 73 22 20 2d 70 22 25 73 22 20 2d 6f 2d 20 2d 73 20 2d 64 22 25 73 } //2 %s" -p"%s" -o- -s -d"%s
		$a_01_9 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*6+(#a_01_1  & 1)*6+(#a_01_2  & 1)*6+(#a_01_3  & 1)*4+(#a_01_4  & 1)*4+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*1) >=19
 
}