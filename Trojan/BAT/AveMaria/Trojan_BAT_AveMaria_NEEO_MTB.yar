
rule Trojan_BAT_AveMaria_NEEO_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {11 07 75 15 00 00 01 14 17 8d 02 00 00 01 25 16 03 a2 6f 80 00 00 0a 74 42 00 00 01 13 08 1b 13 0e 2b be } //05 00 
		$a_01_1 = {61 6e 6e 6f 74 20 79 65 20 72 75 6e } //00 00  annot ye run
	condition:
		any of ($a_*)
 
}