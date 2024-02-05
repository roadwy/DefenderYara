
rule Trojan_BAT_DarkTortilla_AAIJ_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {17 da 0c 2b 47 07 19 5d 16 fe 01 13 04 11 04 2c 0b 02 07 02 07 91 1f 1a 61 b4 9c 00 00 02 07 91 0d 08 19 5d 16 fe 01 13 05 11 05 2c 0b 02 08 02 08 91 1f 1a 61 b4 9c 00 00 02 07 02 08 91 9c 02 08 09 9c 07 17 d6 0b 08 17 da 0c 00 07 08 fe 04 13 06 11 06 2d af } //00 00 
	condition:
		any of ($a_*)
 
}