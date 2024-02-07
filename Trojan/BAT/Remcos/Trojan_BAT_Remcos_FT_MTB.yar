
rule Trojan_BAT_Remcos_FT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 09 20 00 01 00 00 5d 13 09 38 90 01 04 11 06 11 01 11 01 9e 38 90 01 04 11 07 11 01 02 11 01 91 11 03 61 d2 9c 38 90 00 } //01 00 
		$a_81_1 = {66 31 33 6d 64 50 6f 64 65 4e } //01 00  f13mdPodeN
		$a_81_2 = {4e 6f 77 6f 72 63 61 66 6f 72 61 62 } //00 00  Noworcaforab
	condition:
		any of ($a_*)
 
}