
rule Trojan_BAT_CoinMiner_MBDP_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MBDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 48 08 00 70 72 cb 01 00 70 28 90 01 01 00 00 06 72 4c 08 00 70 72 52 08 00 70 90 00 } //1
		$a_03_1 = {11 02 11 04 18 6f 90 01 01 00 00 0a 20 90 01 01 02 00 00 28 90 01 01 00 00 06 13 06 38 90 01 03 ff 02 7b 90 01 01 00 00 04 1f 25 1f 17 73 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 38 90 01 03 ff 02 73 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}