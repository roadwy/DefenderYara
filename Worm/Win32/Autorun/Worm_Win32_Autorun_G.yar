
rule Worm_Win32_Autorun_G{
	meta:
		description = "Worm:Win32/Autorun.G,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8a 00 ffffff89 00 0c 00 00 0a 00 "
		
	strings :
		$a_00_0 = {51 75 65 72 79 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32 } //0a 00  QueryServiceConfig2
		$a_00_1 = {43 68 61 6e 67 65 53 65 72 76 69 63 65 43 6f 6e 66 69 67 32 } //0a 00  ChangeServiceConfig2
		$a_00_2 = {64 72 69 76 65 72 73 2f 6b 6c 69 66 2e 73 79 73 } //01 00  drivers/klif.sys
		$a_00_3 = {3a 5c 41 75 74 6f 52 75 6e 2e 69 6e 66 } //01 00  :\AutoRun.inf
		$a_00_4 = {4e 6f 44 72 69 76 65 54 79 70 65 41 75 74 6f 52 75 6e } //01 00  NoDriveTypeAutoRun
		$a_00_5 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_00_6 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d } //01 00  shellexecute=
		$a_01_7 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d } //01 00  shell\Auto\command=
		$a_00_8 = {73 65 72 76 65 72 69 65 } //01 00  serverie
		$a_00_9 = {63 6d 64 20 2f 63 20 64 61 74 65 } //01 00  cmd /c date
		$a_00_10 = {5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 69 6e 74 65 72 6e 65 74 20 65 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 } //64 00  \program files\internet explorer\IEXPLORE.EXE
		$a_00_11 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //00 00  SOFTWARE\Borland\Delphi\RTL
	condition:
		any of ($a_*)
 
}