
rule Worm_Win32_Delf_BD{
	meta:
		description = "Worm:Win32/Delf.BD,SIGNATURE_TYPE_PEHSTR,4c 00 4c 00 0e 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 4c 6f 63 61 6c 65 73 } //0a 00  Software\Borland\Delphi\Locales
		$a_01_1 = {53 65 78 79 20 47 69 72 6c 73 2e 73 63 72 } //0a 00  Sexy Girls.scr
		$a_01_2 = {4f 70 74 69 6d 69 7a 65 72 2e 70 69 66 } //0a 00  Optimizer.pif
		$a_01_3 = {5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //0a 00  \SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_4 = {46 72 61 6d 65 57 6f 72 6b 53 65 72 76 69 63 65 } //0a 00  FrameWorkService
		$a_01_5 = {3a 3a 7b 34 35 30 44 38 46 42 41 2d 41 44 32 35 2d 31 31 44 30 2d 39 38 41 38 2d 30 38 30 30 33 36 31 42 31 31 30 33 7d } //0a 00  ::{450D8FBA-AD25-11D0-98A8-0800361B1103}
		$a_01_6 = {5f 46 69 63 68 69 65 72 73 2e 65 78 65 } //01 00  _Fichiers.exe
		$a_01_7 = {6d 6d 63 2e 65 78 65 } //01 00  mmc.exe
		$a_01_8 = {72 73 74 72 75 69 2e 65 78 65 } //01 00  rstrui.exe
		$a_01_9 = {72 65 67 65 64 69 74 2e 65 78 65 } //01 00  regedit.exe
		$a_01_10 = {72 65 67 65 64 74 33 32 2e 65 78 65 } //01 00  regedt32.exe
		$a_01_11 = {4e 6f 46 6f 6c 64 65 72 4f 70 74 69 6f 6e 73 } //01 00  NoFolderOptions
		$a_01_12 = {4e 6f 52 75 6e } //01 00  NoRun
		$a_01_13 = {4e 6f 46 69 6e 64 } //00 00  NoFind
	condition:
		any of ($a_*)
 
}