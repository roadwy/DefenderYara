
rule Trojan_BAT_DarkTortilla_K_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 07 8c 90 01 01 00 00 01 a2 25 17 11 04 6a 23 90 00 } //02 00 
		$a_03_1 = {00 00 0a b9 61 8c 90 01 01 00 00 01 a2 14 28 90 01 01 00 00 0a 18 13 07 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}