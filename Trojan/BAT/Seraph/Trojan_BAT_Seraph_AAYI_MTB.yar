
rule Trojan_BAT_Seraph_AAYI_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 16 2c 43 26 06 8e 69 1c 2c 19 16 2d 2f 8d ?? 00 00 01 16 2c 34 26 16 15 2d 32 26 15 2c e6 06 8e 69 17 59 16 2c 29 26 2b 14 07 08 06 09 91 9c 08 16 2d d4 17 58 16 2c 1a 26 09 17 59 0d 09 16 2f e8 07 13 04 de 15 0a 2b bb 0b 2b ca 0c 2b cc 0d 2b d5 0c 2b e4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}