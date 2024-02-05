
rule Trojan_BAT_Remcos_ALA_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 01 2a 00 72 0d 00 00 70 28 0d 00 00 06 13 00 38 00 00 00 00 28 14 00 00 0a 11 00 6f 15 00 00 0a 28 16 00 00 0a 28 0b 00 00 06 13 01 } //00 00 
	condition:
		any of ($a_*)
 
}