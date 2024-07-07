
rule Trojan_BAT_CoinMiner_PSCD_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.PSCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 ac 04 00 70 28 1e 00 00 0a 72 af 06 00 70 6f 1f 90 01 03 1f 64 73 20 90 01 03 1f 10 6f 21 90 01 03 0a 28 22 90 01 03 0b 73 23 90 01 03 0c 08 03 2d 18 07 06 28 1e 90 01 03 72 f1 06 00 70 6f 1f 90 01 03 6f 24 90 01 03 2b 16 07 06 28 1e 90 01 03 72 f1 06 00 70 6f 1f 90 01 03 6f 25 90 01 03 17 73 26 90 01 03 0d 09 02 16 02 8e 69 6f 27 90 01 03 09 6f 28 90 01 03 de 0a 09 2c 06 09 6f 14 90 01 03 dc 08 6f 29 90 01 03 13 04 de 14 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}