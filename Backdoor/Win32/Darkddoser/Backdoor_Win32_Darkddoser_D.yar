
rule Backdoor_Win32_Darkddoser_D{
	meta:
		description = "Backdoor:Win32/Darkddoser.D,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //05 00  :\autorun.inf
		$a_01_1 = {64 64 6f 73 65 72 } //01 00  ddoser
		$a_01_2 = {41 44 44 4e 45 57 7c 49 64 6c 65 } //01 00  ADDNEW|Idle
		$a_01_3 = {44 4f 57 4e 43 4f 4d 50 7c } //01 00  DOWNCOMP|
		$a_01_4 = {53 59 4e 53 74 61 72 74 } //01 00  SYNStart
		$a_01_5 = {55 53 42 7c 49 6e 66 65 63 74 65 64 20 44 72 69 76 65 } //00 00  USB|Infected Drive
		$a_00_6 = {80 10 00 00 f4 6b d4 62 d5 35 } //c6 cf 
	condition:
		any of ($a_*)
 
}