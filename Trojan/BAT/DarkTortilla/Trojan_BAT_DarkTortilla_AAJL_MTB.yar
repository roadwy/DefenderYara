
rule Trojan_BAT_DarkTortilla_AAJL_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {05 0c 16 0d 2b 38 03 09 91 13 04 09 1d 5d 13 05 07 11 05 9a 13 06 03 09 02 11 06 11 04 28 90 01 01 00 00 06 9c 09 05 fe 01 13 07 11 07 2c 0c 7e 90 01 01 00 00 04 28 90 01 02 00 06 0a 00 00 09 17 d6 0d 09 08 31 c4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}