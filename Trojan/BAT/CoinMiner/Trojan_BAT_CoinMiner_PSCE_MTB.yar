
rule Trojan_BAT_CoinMiner_PSCE_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.PSCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 e8 07 00 70 28 25 90 01 03 72 eb 09 00 70 6f 26 90 01 03 1f 64 73 27 90 01 03 1f 10 6f 28 90 01 03 0a 28 29 90 01 03 0b 73 2a 90 01 03 0c 08 03 2d 18 07 06 28 25 90 01 03 72 2d 0a 00 70 6f 26 90 01 03 6f 2b 90 01 03 2b 16 07 06 28 25 90 01 03 72 2d 0a 00 70 6f 26 90 01 03 6f 2c 90 01 03 17 73 2d 90 01 03 0d 09 02 16 02 8e 69 6f 2e 90 01 03 09 6f 2f 90 01 03 de 0a 09 2c 06 09 6f 13 90 01 03 dc 08 6f 30 90 01 03 13 04 de 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}