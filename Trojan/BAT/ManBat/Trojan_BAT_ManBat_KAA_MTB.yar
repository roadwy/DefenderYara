
rule Trojan_BAT_ManBat_KAA_MTB{
	meta:
		description = "Trojan:BAT/ManBat.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 04 11 08 11 04 11 08 91 07 11 08 91 61 9c 11 08 17 d6 13 08 } //00 00 
	condition:
		any of ($a_*)
 
}