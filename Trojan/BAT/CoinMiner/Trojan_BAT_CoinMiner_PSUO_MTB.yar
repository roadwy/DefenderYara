
rule Trojan_BAT_CoinMiner_PSUO_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.PSUO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 20 e0 7d 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 20 04 00 00 00 38 42 ff ff ff 00 11 02 11 09 17 73 0f 00 00 0a 13 03 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}