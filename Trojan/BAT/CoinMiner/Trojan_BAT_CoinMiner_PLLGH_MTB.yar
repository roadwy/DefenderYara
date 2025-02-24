
rule Trojan_BAT_CoinMiner_PLLGH_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.PLLGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 27 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 58 0c 08 02 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}