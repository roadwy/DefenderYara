
rule Trojan_BAT_DarkTortilla_AAWR_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAWR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {04 0b 16 0c 2b 1e 02 08 91 0d 08 1d 5d 13 04 03 11 04 9a 13 05 02 08 11 05 09 28 90 01 01 00 00 06 9c 08 17 d6 0c 08 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}