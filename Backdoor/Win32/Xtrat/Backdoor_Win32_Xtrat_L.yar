
rule Backdoor_Win32_Xtrat_L{
	meta:
		description = "Backdoor:Win32/Xtrat.L,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {58 00 74 00 72 00 65 00 6d 00 65 00 } //01 00  Xtreme
		$a_00_1 = {45 00 42 00 49 00 4e 00 44 00 45 00 52 00 } //01 00  EBINDER
		$a_01_2 = {75 6e 69 74 4b 65 79 6c 6f 67 67 65 72 } //01 00  unitKeylogger
		$a_00_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 46 00 61 00 6b 00 65 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00 } //01 00  SOFTWARE\FakeMessage
		$a_00_4 = {5b 00 43 00 4c 00 49 00 50 00 42 00 4f 00 41 00 52 00 44 00 5d 00 20 00 2d 00 2d 00 } //01 00  [CLIPBOARD] --
		$a_00_5 = {4e 00 4f 00 49 00 4e 00 4a 00 45 00 43 00 54 00 25 00 } //00 00  NOINJECT%
		$a_00_6 = {80 10 00 } //00 9d 
	condition:
		any of ($a_*)
 
}