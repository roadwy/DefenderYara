
rule Trojan_BAT_Spynoon_BXAA_MTB{
	meta:
		description = "Trojan:BAT/Spynoon.BXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 13 08 11 06 13 09 11 08 11 09 fe 02 16 fe 01 13 16 11 16 2d 03 00 2b 22 11 04 11 07 09 11 07 1e 5a 1e 6f 90 01 01 00 00 0a 18 28 90 01 01 00 00 0a 9c 11 07 17 58 13 07 00 17 13 16 2b c3 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}