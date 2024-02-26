
rule Trojan_BAT_njRAT_RDY_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {17 28 07 00 00 0a 7e 04 00 00 04 28 08 00 00 0a 26 } //00 00 
	condition:
		any of ($a_*)
 
}