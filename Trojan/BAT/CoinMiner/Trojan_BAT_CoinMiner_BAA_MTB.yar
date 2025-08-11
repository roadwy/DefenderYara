
rule Trojan_BAT_CoinMiner_BAA_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 14 00 00 0a 0a 06 8e 69 8d 17 00 00 01 0b 06 06 8e 69 20 9a 02 00 00 59 07 16 20 4d 01 00 00 28 15 00 00 0a 06 16 07 20 4d 01 00 00 06 8e 69 20 9a 02 00 00 59 28 15 00 00 0a 06 06 8e 69 20 4d 01 00 00 59 07 06 8e 69 20 4d 01 00 00 59 20 4d 01 00 00 28 15 00 00 0a 07 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}