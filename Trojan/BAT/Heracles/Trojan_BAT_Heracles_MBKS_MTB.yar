
rule Trojan_BAT_Heracles_MBKS_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 65 00 73 00 74 00 31 00 32 00 2e 00 43 00 6c 00 61 00 73 00 73 00 31 00 00 13 46 00 69 00 6b 00 72 00 61 00 68 00 61 00 63 00 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_MBKS_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.MBKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {91 09 07 09 8e 69 6a 5d d4 91 61 06 07 17 6a 58 06 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 08 06 07 06 8e 69 6a 5d d4 11 08 20 00 01 00 00 5d d2 9c 07 17 6a 58 0b } //00 00 
	condition:
		any of ($a_*)
 
}