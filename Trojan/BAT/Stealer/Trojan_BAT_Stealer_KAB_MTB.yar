
rule Trojan_BAT_Stealer_KAB_MTB{
	meta:
		description = "Trojan:BAT/Stealer.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 0d 11 0d 11 08 16 11 08 8e 69 6f 90 01 01 00 00 0a 13 0e 28 90 01 01 00 00 0a 11 0e 6f 90 01 01 00 00 0a 80 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}