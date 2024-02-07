
rule Worm_Win32_Autorun_BS{
	meta:
		description = "Worm:Win32/Autorun.BS,SIGNATURE_TYPE_PEHSTR,22 00 22 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 65 74 2e 65 78 65 } //0a 00  servet.exe
		$a_01_1 = {64 72 69 76 65 72 73 2f 6b 6c 69 63 6b 2e 73 79 73 } //0a 00  drivers/klick.sys
		$a_01_2 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //01 00  ZwUnmapViewOfSection
		$a_01_3 = {5c 43 24 5c 41 75 74 6f 45 78 65 63 2e 62 61 74 } //01 00  \C$\AutoExec.bat
		$a_01_4 = {69 66 20 65 78 69 73 74 20 22 } //01 00  if exist "
		$a_01_5 = {20 67 6f 74 6f 20 74 72 79 } //01 00   goto try
		$a_01_6 = {44 65 6c 65 74 65 6d 65 2e 62 61 74 } //01 00  Deleteme.bat
		$a_01_7 = {62 61 74 73 65 72 2e 62 61 74 } //01 00  batser.bat
		$a_01_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 } //00 00  Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
	condition:
		any of ($a_*)
 
}