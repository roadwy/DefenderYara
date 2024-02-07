
rule TrojanDownloader_Win32_Zlob_IF{
	meta:
		description = "TrojanDownloader:Win32/Zlob.IF,SIGNATURE_TYPE_PEHSTR,1a 00 1a 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4e 65 74 50 72 6f 6a 65 63 74 } //01 00  Software\NetProject
		$a_01_1 = {67 6f 6f 67 6c 65 2e } //01 00  google.
		$a_01_2 = {33 2d 30 30 43 30 34 46 37 39 46 41 41 36 7d 00 34 41 2d 31 31 44 33 2d 42 31 35 00 7b 36 42 46 35 32 41 35 32 2d 33 39 } //01 00  ⴳ〰ぃ䘴㤷䅆㙁}䄴ㄭ䐱ⴳㅂ5㙻䙂㈵㕁ⴲ㤳
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 65 61 72 63 68 53 63 6f 70 65 73 } //01 00  Software\Microsoft\Internet Explorer\SearchScopes
		$a_01_4 = {61 77 65 72 25 64 2e 62 61 74 } //0a 00  awer%d.bat
		$a_01_5 = {3a 52 65 70 65 61 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 0d 0a 72 6d 64 69 72 20 22 25 73 22 } //0a 00 
		$a_01_6 = {25 73 5c 7a 66 25 73 25 64 2e 65 78 65 } //01 00  %s\zf%s%d.exe
		$a_01_7 = {2e 63 68 6c 5c 43 4c 53 49 44 } //00 00  .chl\CLSID
	condition:
		any of ($a_*)
 
}