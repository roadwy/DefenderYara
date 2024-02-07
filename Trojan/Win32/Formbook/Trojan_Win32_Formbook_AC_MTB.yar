
rule Trojan_Win32_Formbook_AC_MTB{
	meta:
		description = "Trojan:Win32/Formbook.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 00 45 00 4c 00 4f 00 50 00 48 00 4f 00 42 00 49 00 41 00 } //01 00  ZELOPHOBIA
		$a_01_1 = {52 00 65 00 74 00 75 00 72 00 70 00 6f 00 72 00 74 00 6f 00 65 00 6e 00 35 00 } //01 00  Returportoen5
		$a_01_2 = {66 00 69 00 6c 00 69 00 61 00 6c 00 69 00 74 00 79 00 } //01 00  filiality
		$a_00_3 = {43 44 73 61 43 44 73 39 67 44 73 } //01 00  CDsaCDs9gDs
		$a_00_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_01_5 = {73 00 75 00 73 00 70 00 65 00 63 00 74 00 65 00 64 00 } //01 00  suspected
		$a_01_6 = {53 00 71 00 75 00 65 00 6c 00 63 00 68 00 65 00 72 00 31 00 } //00 00  Squelcher1
	condition:
		any of ($a_*)
 
}