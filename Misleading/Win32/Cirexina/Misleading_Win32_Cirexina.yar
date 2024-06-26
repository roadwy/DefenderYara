
rule Misleading_Win32_Cirexina{
	meta:
		description = "Misleading:Win32/Cirexina,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 43 00 20 00 46 00 69 00 78 00 20 00 43 00 6c 00 65 00 61 00 6e 00 65 00 72 00 } //01 00  PC Fix Cleaner
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 43 00 46 00 69 00 78 00 00 00 } //01 00 
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 63 00 2d 00 66 00 69 00 78 00 2d 00 63 00 6c 00 65 00 61 00 6e 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 } //01 00  http://www.pc-fix-cleaner.com/
		$a_01_3 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 4d 00 75 00 74 00 65 00 78 00 57 00 69 00 6e 00 54 00 75 00 72 00 62 00 6f 00 } //00 00  Global\MutexWinTurbo
		$a_00_4 = {78 c5 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Misleading_Win32_Cirexina_2{
	meta:
		description = "Misleading:Win32/Cirexina,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 43 00 46 00 69 00 78 00 42 00 6f 00 6f 00 73 00 74 00 65 00 72 00 } //01 00  Software\PCFixBooster
		$a_01_1 = {50 00 43 00 20 00 46 00 69 00 78 00 20 00 42 00 6f 00 6f 00 73 00 74 00 65 00 72 00 } //01 00  PC Fix Booster
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 63 00 2d 00 66 00 69 00 78 00 2d 00 62 00 6f 00 6f 00 73 00 74 00 65 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 } //01 00  http://www.pc-fix-booster.com/
		$a_01_3 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 4d 00 75 00 74 00 65 00 78 00 57 00 69 00 6e 00 54 00 75 00 72 00 62 00 6f 00 } //00 00  Global\MutexWinTurbo
		$a_00_4 = {e7 31 } //00 00 
	condition:
		any of ($a_*)
 
}