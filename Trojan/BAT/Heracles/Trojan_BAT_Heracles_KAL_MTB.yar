
rule Trojan_BAT_Heracles_KAL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 11 05 08 11 05 91 07 11 04 93 28 90 01 01 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 05 17 58 13 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}