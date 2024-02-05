
rule Trojan_BAT_StormKitty_NEA_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {60 13 07 08 11 06 11 07 1f 18 5b d2 8c 26 00 00 01 6f 0e 01 00 0a 11 07 1f 18 5d 13 05 07 11 04 06 11 05 93 9d 11 06 17 59 } //00 00 
	condition:
		any of ($a_*)
 
}