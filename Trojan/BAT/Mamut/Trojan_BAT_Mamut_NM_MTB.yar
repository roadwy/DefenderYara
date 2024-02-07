
rule Trojan_BAT_Mamut_NM_MTB{
	meta:
		description = "Trojan:BAT/Mamut.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 26 00 00 0a d0 90 01 03 1b 28 90 01 03 0a 28 90 01 03 0a 74 0e 00 90 00 } //01 00 
		$a_01_1 = {50 61 63 6b 6d 61 6e } //00 00  Packman
	condition:
		any of ($a_*)
 
}