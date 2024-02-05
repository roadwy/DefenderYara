
rule Trojan_BAT_DarkTortilla_PSMF_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.PSMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {d0 57 00 00 06 26 18 13 08 2b d6 28 90 01 03 06 0b 28 90 01 03 0a 07 74 90 01 03 1b 6f 90 01 03 0a 28 90 01 03 06 28 90 01 03 0a 17 28 90 01 03 06 75 90 01 03 1b 0c 16 13 08 2b a5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}