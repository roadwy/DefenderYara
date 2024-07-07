
rule Trojan_BAT_CoinMiner_SPAP_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.SPAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 17 6f 90 01 03 0a 11 06 0c 03 2d 11 08 07 1f 10 6f 90 01 03 0a 06 6f 90 01 03 0a 2b 0f 08 07 1f 10 6f 90 01 03 0a 06 6f 90 01 03 0a 0d 73 2f 00 00 0a 13 04 11 04 09 17 73 30 00 00 0a 13 05 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}