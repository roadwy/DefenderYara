
rule Trojan_BAT_CoinMiner_BH_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 14 0b 02 28 ?? 00 00 0a 0b 17 0a de 08 26 de 05 26 17 0a de 00 07 2c 06 07 6f ?? 00 00 0a 06 2a } //4
		$a_01_1 = {4d 75 74 65 78 } //1 Mutex
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}