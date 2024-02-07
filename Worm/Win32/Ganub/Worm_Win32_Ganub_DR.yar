
rule Worm_Win32_Ganub_DR{
	meta:
		description = "Worm:Win32/Ganub.DR,SIGNATURE_TYPE_PEHSTR,23 00 23 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //0a 00  ShellExecuteA
		$a_01_1 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //0a 00  GetTempPathA
		$a_01_2 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 41 } //02 00  GetTempFileNameA
		$a_01_3 = {77 69 6e 64 69 72 25 5c 62 67 31 5c 42 75 6e 67 61 2e 65 78 65 } //02 00  windir%\bg1\Bunga.exe
		$a_01_4 = {62 67 31 5c 64 65 6b 73 74 6f 70 2e 69 6e 69 2e 65 78 65 } //01 00  bg1\dekstop.ini.exe
		$a_01_5 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 46 6c 61 73 68 2e 31 30 2e 65 78 65 20 2f 69 6d 20 4d 61 63 72 6f 6d 65 64 69 61 2e 31 30 2e 65 78 65 } //01 00  taskkill /f /im Flash.10.exe /im Macromedia.10.exe
		$a_01_6 = {2a 20 53 65 6d 62 61 68 79 61 6e 67 20 } //01 00  * Sembahyang 
		$a_01_7 = {4d 41 4b 45 20 50 45 41 43 45 46 55 4c 20 41 4e 44 20 48 41 50 50 49 4e 45 53 53 } //01 00  MAKE PEACEFUL AND HAPPINESS
		$a_01_8 = {73 6f 72 79 20 34 20 65 76 65 72 79 74 68 69 6e 67 } //00 00  sory 4 everything
	condition:
		any of ($a_*)
 
}