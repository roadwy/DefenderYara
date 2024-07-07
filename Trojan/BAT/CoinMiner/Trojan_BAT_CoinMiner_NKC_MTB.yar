
rule Trojan_BAT_CoinMiner_NKC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {6f 0a 00 00 0a 72 90 01 02 00 70 6f 90 01 02 00 0a 73 90 01 02 00 0a 25 6f 90 01 02 00 0a 16 6a 6f 90 01 02 00 0a 25 25 6f 90 01 02 00 0a 6f 90 01 02 00 0a 69 6f 90 01 02 00 0a 13 05 90 00 } //5
		$a_01_1 = {6b 4c 6a 77 34 69 49 73 43 4c 73 5a 74 78 63 34 6c 6b 73 4e 30 6a } //1 kLjw4iIsCLsZtxc4lksN0j
		$a_01_2 = {61 64 64 5f 52 65 73 6f 75 72 63 65 52 65 73 6f 6c 76 65 } //1 add_ResourceResolve
		$a_01_3 = {52 65 6d 6f 76 65 52 65 67 } //1 RemoveReg
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}