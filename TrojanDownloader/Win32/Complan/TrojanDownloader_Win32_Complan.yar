
rule TrojanDownloader_Win32_Complan{
	meta:
		description = "TrojanDownloader:Win32/Complan,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6d 65 64 79 2d 70 6c 61 6e 65 74 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2f 6e 65 74 77 6f 72 6b } //2 http://www.comedy-planet.com/download/network
		$a_00_1 = {63 25 64 2e 65 78 65 } //1 c%d.exe
		$a_00_2 = {2e 70 68 70 3f 6e 3d 25 64 } //1 .php?n=%d
		$a_00_3 = {5c 63 70 2e 65 78 65 } //1 \cp.exe
		$a_01_4 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //1 GetSystemDirectoryA
		$a_00_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_00_6 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}