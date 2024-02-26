
rule Trojan_BAT_Dcstl_EAAA_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.EAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 13 05 11 05 28 90 01 01 00 00 0a 13 06 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 13 07 1a 8d 90 01 01 00 00 01 25 16 20 08 00 00 00 28 90 01 01 00 00 06 a2 25 17 7e 90 01 01 00 00 0a a2 25 18 11 06 a2 25 19 17 8c 90 01 01 00 00 01 a2 13 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}