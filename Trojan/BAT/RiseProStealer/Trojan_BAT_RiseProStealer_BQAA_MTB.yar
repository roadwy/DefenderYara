
rule Trojan_BAT_RiseProStealer_BQAA_MTB{
	meta:
		description = "Trojan:BAT/RiseProStealer.BQAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 09 11 06 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 07 02 11 05 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 06 11 07 91 61 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}