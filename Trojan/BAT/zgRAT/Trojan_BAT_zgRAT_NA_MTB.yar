
rule Trojan_BAT_zgRAT_NA_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {61 19 11 1b 58 61 11 90 01 01 61 d2 9c 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}