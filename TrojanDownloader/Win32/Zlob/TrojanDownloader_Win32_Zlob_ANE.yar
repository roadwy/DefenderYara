
rule TrojanDownloader_Win32_Zlob_ANE{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANE,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_00_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 53 63 6f 70 65 73 } //1 Software\Microsoft\Internet Explorer\SearchScopes
		$a_00_1 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //1 if exist "%s" goto Repeat
		$a_00_2 = {64 65 6c 20 22 25 73 22 } //1 del "%s"
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4e 65 74 50 72 6f 6a 65 63 74 } //1 Software\NetProject
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_5 = {25 73 5c 7a 66 25 73 25 64 2e 65 78 65 } //1 %s\zf%s%d.exe
		$a_00_6 = {5f 63 6c 73 25 64 2e 62 61 74 } //1 _cls%d.bat
		$a_00_7 = {72 6d 64 69 72 20 22 25 73 22 } //1 rmdir "%s"
		$a_00_8 = {2f 6d 75 73 69 63 2e 70 68 70 3f 70 61 72 61 6d 3d } //1 /music.php?param=
		$a_00_9 = {2e 63 68 6c 5c 43 4c 53 49 44 } //1 .chl\CLSID
		$a_00_10 = {79 61 68 6f 6f 2e 00 00 67 6f 6f 67 6c 65 2e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=11
 
}