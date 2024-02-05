
rule TrojanClicker_Win32_VB_GE{
	meta:
		description = "TrojanClicker:Win32/VB.GE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4e 4f 55 53 45 00 90 01 04 74 68 65 70 75 62 6c 69 63 65 72 90 00 } //01 00 
		$a_01_1 = {77 69 6e 72 65 73 00 53 65 74 75 70 00 00 73 65 74 75 70 00 } //01 00 
		$a_01_2 = {2f 00 75 00 70 00 64 00 61 00 74 00 65 00 00 00 18 00 00 00 52 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 } //00 00 
	condition:
		any of ($a_*)
 
}