
rule Trojan_BAT_SpyNoon_SA_MTB{
	meta:
		description = "Trojan:BAT/SpyNoon.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {02 07 02 8e 69 6a 5d d4 02 07 02 8e 69 6a 5d d4 91 06 07 06 8e 69 6a 5d d4 91 61 28 90 02 04 02 07 17 6a 58 02 8e 69 6a 5d d4 91 28 90 02 04 59 20 90 02 04 58 20 90 02 04 5e 28 90 02 04 9c 00 07 17 6a 58 0b 07 02 8e 69 17 59 6a 03 17 58 6e 5a fe 02 16 fe 01 0c 08 2d a0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}