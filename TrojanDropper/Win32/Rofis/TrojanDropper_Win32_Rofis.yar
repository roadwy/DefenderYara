
rule TrojanDropper_Win32_Rofis{
	meta:
		description = "TrojanDropper:Win32/Rofis,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 02 00 00 80 ff 90 02 05 0f 90 02 10 51 56 6a 03 50 68 90 01 04 52 ff 90 00 } //01 00 
		$a_02_1 = {6a 00 6a 00 6a 03 6a 00 6a 07 68 00 00 00 80 68 90 01 04 ff 15 90 00 } //01 00 
		$a_02_2 = {6a 00 6a 05 68 90 01 04 ff 15 90 01 04 50 ff 15 90 01 04 ff d0 0f 31 90 00 } //01 00 
		$a_01_3 = {73 66 63 2e 64 6c 6c } //01 00  sfc.dll
		$a_01_4 = {52 65 67 53 65 74 56 61 6c 75 65 45 78 41 } //01 00  RegSetValueExA
		$a_00_5 = {53 68 65 6c 6c 43 6f 64 65 5c 78 52 65 6c 65 61 73 65 5c 53 68 65 6c 6c 43 6f 64 65 2e 70 64 62 } //00 00  ShellCode\xRelease\ShellCode.pdb
	condition:
		any of ($a_*)
 
}