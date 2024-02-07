
rule Worm_Win32_Autorun_BQ{
	meta:
		description = "Worm:Win32/Autorun.BQ,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 61 6a 61 44 69 72 61 6a 61 } //01 00  RajaDiraja
		$a_01_1 = {4d 61 69 6e 4d 6f 64 75 6c 65 } //01 00  MainModule
		$a_01_2 = {50 61 73 75 6b 61 6e } //01 00  Pasukan
		$a_01_3 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //01 00  GetSystemDirectoryA
		$a_01_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //01 00  ShellExecuteA
		$a_01_5 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_01_6 = {40 00 2a 00 5c 00 41 00 44 00 3a 00 5c 00 42 00 74 00 65 00 6e 00 64 00 5c 00 50 00 41 00 53 00 55 00 4b 00 41 00 4e 00 5c 00 50 00 61 00 73 00 75 00 6b 00 61 00 6e 00 2e 00 76 00 62 00 70 00 } //01 00  @*\AD:\Btend\PASUKAN\Pasukan.vbp
		$a_01_7 = {4e 00 6f 00 74 00 53 00 74 00 61 00 72 00 74 00 58 00 } //00 00  NotStartX
	condition:
		any of ($a_*)
 
}