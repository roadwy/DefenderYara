
rule Trojan_BAT_CoinMiner_ARA_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 09 02 09 91 06 61 03 08 91 61 28 90 01 03 0a 9c 08 03 8e 69 17 59 33 04 16 0c 2b 04 08 17 58 0c 09 17 58 0d 09 02 8e 69 17 59 31 d3 90 00 } //5
		$a_80_1 = {65 74 63 2e 32 6d 69 6e 65 72 73 2e 63 6f 6d 3a 31 30 31 30 } //etc.2miners.com:1010  5
	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}