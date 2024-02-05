
rule Trojan_BAT_QuasarRat_RPY_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 08 02 8e 69 5d 90 01 05 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 90 01 05 02 08 18 58 17 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 19 58 18 59 20 00 01 00 00 5d d2 9c 08 17 58 1a 2d 38 26 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 ad 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}