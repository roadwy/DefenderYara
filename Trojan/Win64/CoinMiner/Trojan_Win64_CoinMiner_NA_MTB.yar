
rule Trojan_Win64_CoinMiner_NA_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {4d 69 63 72 6f 42 69 74 63 6f 69 6e } //5 MicroBitcoin
		$a_81_1 = {67 65 74 6d 69 6e 69 6e 67 69 6e 66 6f } //5 getmininginfo
		$a_81_2 = {79 65 73 63 72 79 70 74 72 33 32 } //2 yescryptr32
		$a_81_3 = {42 69 74 5a 65 6e 79 } //2 BitZeny
		$a_81_4 = {4d 69 6e 65 72 20 74 68 72 65 61 64 20 70 72 69 6f 72 69 74 79 } //1 Miner thread priority
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1) >=15
 
}