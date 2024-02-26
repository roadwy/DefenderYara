
rule Trojan_BAT_Heracles_KAE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 0e 11 11 11 0e 11 11 91 1f 45 61 d2 9c 11 11 17 58 13 11 11 11 11 0e 8e 69 32 e4 } //00 00 
	condition:
		any of ($a_*)
 
}