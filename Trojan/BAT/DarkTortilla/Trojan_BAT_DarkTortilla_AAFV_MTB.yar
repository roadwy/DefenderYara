
rule Trojan_BAT_DarkTortilla_AAFV_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AAFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 08 1a 5d 16 fe 01 13 05 11 05 2c 1d 07 11 04 1f 29 8c 90 01 01 00 00 01 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 00 2b 10 00 07 11 04 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 00 08 17 d6 0c 00 09 6f 90 01 01 00 00 0a 13 06 11 06 2d a9 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}