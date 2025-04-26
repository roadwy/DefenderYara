
rule Trojan_BAT_CoinMiner_NCE_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e ?? ?? 00 04 0e 06 17 59 e0 95 58 0e 05 28 4a 1e 00 06 58 } //5
		$a_01_1 = {6e 57 56 41 63 6f 74 39 41 6f 71 4e 53 46 45 51 41 35 2e 36 57 6a 79 58 4b 68 36 4b 4b 30 76 39 35 65 4a 53 69 } //1 nWVAcot9AoqNSFEQA5.6WjyXKh6KK0v95eJSi
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}