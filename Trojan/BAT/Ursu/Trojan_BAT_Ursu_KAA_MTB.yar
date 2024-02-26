
rule Trojan_BAT_Ursu_KAA_MTB{
	meta:
		description = "Trojan:BAT/Ursu.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5f 69 95 61 d2 9c 11 90 01 01 17 58 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}