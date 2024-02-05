
rule TrojanClicker_Win32_VB_DF{
	meta:
		description = "TrojanClicker:Win32/VB.DF,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 00 61 00 6f 00 6a 00 69 00 6c 00 6d 00 2e 00 63 00 6f 00 6d 00 3a 00 38 00 31 00 2f 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 66 69 6c 65 52 75 6e 79 } //01 00 
		$a_00_2 = {51 00 69 00 78 00 69 00 32 00 30 00 31 00 30 00 53 00 65 00 74 00 75 00 70 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_3 = {72 00 65 00 66 00 65 00 72 00 65 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}