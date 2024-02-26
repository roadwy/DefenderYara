
rule Trojan_BAT_Spynoon_CDAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.CDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 04 11 09 94 13 0a 09 11 09 09 8e 69 5d 91 13 0b 11 05 11 09 11 0a 11 0b 66 5f 11 0a 66 11 0b 5f 60 9e 00 11 09 17 58 13 09 11 09 11 04 8e 69 fe 04 13 0c 11 0c 2d c7 } //00 00 
	condition:
		any of ($a_*)
 
}