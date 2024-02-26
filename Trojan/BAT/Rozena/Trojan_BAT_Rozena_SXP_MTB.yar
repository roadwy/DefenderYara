
rule Trojan_BAT_Rozena_SXP_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {08 11 09 08 11 09 91 18 59 20 90 01 03 00 5f d2 9c 00 11 09 17 58 13 09 11 09 08 8e 69 fe 04 13 0a 11 0a 2d da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}