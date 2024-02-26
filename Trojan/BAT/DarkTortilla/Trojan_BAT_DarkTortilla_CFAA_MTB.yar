
rule Trojan_BAT_DarkTortilla_CFAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.CFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 11 05 11 04 12 05 28 90 01 01 00 00 0a 13 07 1c 13 09 90 0a 21 00 07 75 90 01 01 00 00 1b 08 28 90 01 01 00 00 0a 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}