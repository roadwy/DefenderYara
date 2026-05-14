
rule Trojan_Win64_CoinMiner_MKB_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_81_0 = {43 6f 72 76 75 73 4d 69 6e 65 72 2f 31 2e 30 } //15 CorvusMiner/1.0
		$a_01_1 = {5b 2d 5d 20 58 4d 52 69 67 20 69 6e 6a 65 63 74 69 6f 6e 20 66 61 69 6c 65 64 } //10 [-] XMRig injection failed
		$a_01_2 = {5b 2d 5d 20 47 4d 69 6e 65 72 20 69 6e 6a 65 63 74 69 6f 6e 20 66 61 69 6c 65 64 } //3 [-] GMiner injection failed
		$a_01_3 = {5b 2a 5d 20 43 50 55 20 6d 69 6e 69 6e 67 20 64 69 73 61 62 6c 65 64 2c 20 73 6b 69 70 70 69 6e 67 20 58 4d 52 69 67 20 69 6e 6a 65 63 74 69 6f 6e } //2 [*] CPU mining disabled, skipping XMRig injection
	condition:
		((#a_81_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=30
 
}