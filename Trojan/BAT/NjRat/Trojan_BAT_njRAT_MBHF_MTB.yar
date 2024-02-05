
rule Trojan_BAT_njRAT_MBHF_MTB{
	meta:
		description = "Trojan:BAT/njRAT.MBHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 0a 03 09 03 28 90 01 01 00 00 0a 6a 5d 17 6a 58 69 17 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0b 11 04 06 07 61 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 04 09 17 6a 58 0d 09 11 06 31 a5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}