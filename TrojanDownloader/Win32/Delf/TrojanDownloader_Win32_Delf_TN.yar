
rule TrojanDownloader_Win32_Delf_TN{
	meta:
		description = "TrojanDownloader:Win32/Delf.TN,SIGNATURE_TYPE_PEHSTR,72 00 72 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 31 2e 69 6e 66 } //01 00  \1.inf
		$a_01_1 = {5c 64 72 65 61 6d 2e 65 78 65 } //01 00  \dream.exe
		$a_01_2 = {6d 65 6c 6f 76 65 } //01 00  melove
		$a_01_3 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 5c } //01 00  \autorun.inf\
		$a_01_4 = {4f 50 45 4e 3d 73 62 6c 2e 65 78 65 } //01 00  OPEN=sbl.exe
		$a_01_5 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 73 62 6c 2e 65 78 65 } //01 00  shellexecute=sbl.exe
		$a_01_6 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 73 62 6c 2e 65 78 65 } //01 00  shell\Auto\command=sbl.exe
		$a_01_7 = {63 6d 64 2e 65 78 65 20 2f 63 20 6e 65 74 20 73 74 6f 70 20 73 68 61 72 65 64 61 63 63 65 73 73 } //01 00  cmd.exe /c net stop sharedaccess
		$a_01_8 = {5c 70 6c 6d 6d 73 62 6c 2e 64 6c 6c } //01 00  \plmmsbl.dll
		$a_01_9 = {5c 41 6e 48 61 6f 5c 61 6e 74 69 61 75 74 6f 72 75 6e } //01 00  \AnHao\antiautorun
		$a_01_10 = {6d 79 6c 6f 76 65 67 69 72 6c 73 62 6c } //01 00  mylovegirlsbl
		$a_01_11 = {63 3a 5c 61 2e 65 78 65 } //01 00  c:\a.exe
		$a_01_12 = {63 3a 5c 62 2e 65 78 65 } //01 00  c:\b.exe
		$a_01_13 = {63 3a 5c 63 2e 65 78 65 } //64 00  c:\c.exe
		$a_01_14 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00  SOFTWARE\Borland\Delphi\RTL
	condition:
		any of ($a_*)
 
}