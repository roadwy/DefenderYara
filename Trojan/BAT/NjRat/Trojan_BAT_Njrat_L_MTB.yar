
rule Trojan_BAT_Njrat_L_MTB{
	meta:
		description = "Trojan:BAT/Njrat.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 11 07 11 07 08 91 11 07 09 91 d6 90 01 05 5f 91 06 11 04 91 61 9c 2b 07 13 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}