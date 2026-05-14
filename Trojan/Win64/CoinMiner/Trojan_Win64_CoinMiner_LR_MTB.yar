
rule Trojan_Win64_CoinMiner_LR_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 "
		
	strings :
		$a_81_0 = {43 6f 72 76 75 73 4d 69 6e 65 72 2f 31 2e 30 } //1 CorvusMiner/1.0
		$a_81_1 = {63 6f 72 76 75 73 2e 65 78 65 } //2 corvus.exe
		$a_01_2 = {48 8b c2 83 e0 3f 42 0f b6 44 00 10 41 30 04 11 48 ff c2 49 3b d2 } //10
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_01_2  & 1)*10) >=13
 
}