
rule Trojan_BAT_CoinMiner_SX_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 07 03 8e 69 fe 01 0d 09 2c 04 00 16 0b 00 06 08 02 08 91 03 07 93 28 ?? 01 00 0a 61 d2 9c 07 17 58 0b 00 08 17 58 0c } //30
		$a_03_1 = {07 0c 08 2c 05 00 17 0d de 78 7e ?? 00 00 04 1f 64 6f ?? 00 00 0a 13 04 11 04 2c 05 00 17 0d de 61 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}