
rule Trojan_BAT_ZgRat_RPX_MTB{
	meta:
		description = "Trojan:BAT/ZgRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 14 11 15 11 15 07 58 9e 11 15 17 58 13 15 11 15 11 14 8e 69 32 e9 11 11 17 58 13 11 11 11 03 8e 69 3f 52 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}