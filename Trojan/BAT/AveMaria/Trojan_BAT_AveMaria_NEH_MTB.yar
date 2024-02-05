
rule Trojan_BAT_AveMaria_NEH_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 58 13 04 2b 03 0b 2b 90 01 01 11 04 06 8e 69 32 02 2b 05 2b cc 0a 2b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}