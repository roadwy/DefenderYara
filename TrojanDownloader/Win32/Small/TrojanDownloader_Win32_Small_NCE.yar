
rule TrojanDownloader_Win32_Small_NCE{
	meta:
		description = "TrojanDownloader:Win32/Small.NCE,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 65 6d 74 65 73 74 33 32 2e 73 79 73 } //01 00  memtest32.sys
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 79 70 65 64 55 72 6c 73 } //01 00  Software\Microsoft\Internet Explorer\TypedUrls
		$a_01_3 = {53 70 79 77 61 72 65 47 75 61 72 64 50 6c 75 73 } //01 00  SpywareGuardPlus
		$a_01_4 = {5b 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 5d } //01 00  [InternetShortcut]
		$a_01_5 = {61 63 61 6f 77 69 65 75 62 3d 31 3b 20 65 78 70 69 72 65 73 3d } //01 00  acaowieub=1; expires=
		$a_01_6 = {73 79 73 74 65 6d 33 32 5c 66 61 76 69 63 6f 2e 64 61 74 } //01 00  system32\favico.dat
		$a_01_7 = {45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00  Explorer\iexplore.exe
		$a_01_8 = {89 78 1a 50 54 51 56 50 68 00 10 00 00 51 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}