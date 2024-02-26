
rule Trojan_BAT_DarkTortilla_AAXD_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 19 13 0a 2b a8 09 75 90 01 01 00 00 01 09 74 90 01 01 00 00 01 6f 90 01 01 00 00 0a 09 74 90 01 01 00 00 01 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 04 1b 13 0a 2b 80 90 00 } //02 00 
		$a_03_1 = {11 06 75 61 00 00 01 02 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 16 02 8e 69 6f 90 01 01 00 00 0a 18 13 0e 2b c1 11 06 75 90 01 01 00 00 01 6f 90 01 01 00 00 0a de 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}