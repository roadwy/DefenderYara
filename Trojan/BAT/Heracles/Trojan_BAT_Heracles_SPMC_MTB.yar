
rule Trojan_BAT_Heracles_SPMC_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SPMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {61 08 11 0e 91 59 13 0f 11 0f 20 00 01 00 00 58 13 10 08 07 11 10 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}