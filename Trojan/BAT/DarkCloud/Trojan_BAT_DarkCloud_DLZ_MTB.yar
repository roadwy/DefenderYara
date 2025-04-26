
rule Trojan_BAT_DarkCloud_DLZ_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.DLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 72 c1 01 00 70 28 23 00 00 0a 0d 72 f3 01 00 70 28 ?? 00 00 0a 13 04 73 24 00 00 0a 13 05 73 25 00 00 0a 13 06 11 06 11 05 09 11 04 6f 26 00 00 0a 17 73 ?? 00 00 0a 13 07 2b 16 2b 18 16 2b 18 8e 69 2b 17 17 16 2c 1a 26 2b 1a 2b 1c 13 08 de 70 11 07 2b e6 08 2b e5 08 2b e5 6f ?? 00 00 0a 2b e2 0b 2b e4 11 06 2b e2 6f 29 00 00 0a 2b dd } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}