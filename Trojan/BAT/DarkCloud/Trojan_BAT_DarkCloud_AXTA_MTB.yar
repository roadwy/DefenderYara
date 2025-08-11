
rule Trojan_BAT_DarkCloud_AXTA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AXTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 1a 8d ?? 00 00 01 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 2b 3e 8d ?? 00 00 01 2b 3b 16 2b 3c 2b 15 2b 3c 2b 3e 2b 40 2b 42 2b 44 2b 46 59 6f ?? 00 00 0a 58 13 07 1c 2c 09 11 07 11 04 17 2c f3 32 df 72 ?? ?? 00 70 11 06 03 28 ?? 00 00 06 17 0b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}