
rule Trojan_BAT_DarkTortilla_AAJS_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 07 74 90 01 01 00 00 1b 11 04 1f 09 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 1a 13 09 2b 8f 08 17 d6 0c 1d 13 09 2b 86 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}