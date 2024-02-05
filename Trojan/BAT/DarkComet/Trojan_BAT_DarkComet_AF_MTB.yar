
rule Trojan_BAT_DarkComet_AF_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {0b 02 16 91 0d 19 02 8e b7 17 da 13 05 0a 2b 48 09 02 17 91 fe 01 09 02 17 91 fe 02 60 2c 04 02 16 91 0d 02 06 91 09 da 0c 08 16 2f 08 } //00 00 
	condition:
		any of ($a_*)
 
}