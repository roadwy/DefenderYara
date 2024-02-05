
rule Trojan_BAT_Perseus_KAA_MTB{
	meta:
		description = "Trojan:BAT/Perseus.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {07 11 05 02 11 05 91 08 61 06 11 04 91 61 b4 9c 1e } //05 00 
		$a_01_1 = {b7 17 da 91 1f 70 61 0c 1f 0a 2b 6a 07 } //00 00 
	condition:
		any of ($a_*)
 
}