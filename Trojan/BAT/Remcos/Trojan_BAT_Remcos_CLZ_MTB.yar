
rule Trojan_BAT_Remcos_CLZ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.CLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 3c 00 00 06 0c 72 7a 02 00 70 28 51 00 00 0a 0d 72 ac 02 00 70 28 51 00 00 0a 13 04 73 52 00 00 0a 13 05 73 41 00 00 0a 13 06 11 06 11 05 09 11 04 6f 53 00 00 0a 17 73 54 00 00 0a 13 07 2b 16 2b 18 16 2b 18 8e 69 2b 17 17 16 2c 1a 26 2b 1a 2b 1c 13 08 de 70 11 07 2b e6 08 2b e5 08 2b e5 6f ?? 00 00 0a 2b e2 0b 2b e4 11 06 2b e2 6f ?? 00 00 0a 2b dd 11 07 2c 0a 16 2d 07 11 07 6f 38 00 00 0a 18 2c f3 dc } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}