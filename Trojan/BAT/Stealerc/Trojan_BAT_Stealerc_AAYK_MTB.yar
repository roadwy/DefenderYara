
rule Trojan_BAT_Stealerc_AAYK_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.AAYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {04 06 18 28 90 01 01 01 00 06 7e 90 01 01 01 00 04 06 1b 28 90 01 01 01 00 06 7e 90 01 01 01 00 04 06 28 90 01 01 01 00 06 0d 7e 90 01 01 01 00 04 09 05 16 05 8e 69 28 90 01 01 01 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}