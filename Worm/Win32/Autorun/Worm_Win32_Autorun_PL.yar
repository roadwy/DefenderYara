
rule Worm_Win32_Autorun_PL{
	meta:
		description = "Worm:Win32/Autorun.PL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 00 6f 00 75 00 72 00 6e 00 5f 00 4f 00 70 00 65 00 72 00 61 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00 } //1 Mourn_Operator.exe
		$a_01_1 = {41 00 55 00 54 00 4f 00 52 00 55 00 4e 00 2e 00 49 00 4e 00 46 00 } //1 AUTORUN.INF
		$a_01_2 = {75 72 6e 5f 4f 70 4d 6f 75 72 6e 5f 4f 70 65 72 61 74 6f 72 00 00 } //1
		$a_01_3 = {5b 00 41 00 55 00 54 00 4f 00 52 00 55 00 4e 00 5d 00 } //1 [AUTORUN]
		$a_01_4 = {53 00 59 00 53 00 41 00 4e 00 41 00 4c 00 59 00 53 00 49 00 53 00 2e 00 45 00 58 00 45 00 } //1 SYSANALYSIS.EXE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}