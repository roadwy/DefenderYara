
rule Trojan_BAT_Mallox_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Mallox.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {11 03 11 02 11 04 11 02 8e 69 5d 91 11 01 11 04 91 61 d2 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 } //01 00  WindowsFormsApp
		$a_01_2 = {53 74 77 78 72 6e 7a } //00 00  Stwxrnz
	condition:
		any of ($a_*)
 
}