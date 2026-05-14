
rule Trojan_Win64_CoinMiner_LM_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 07 00 00 "
		
	strings :
		$a_81_0 = {28 28 47 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 29 2e 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 2d 63 6f 6e 74 61 69 6e 73 20 27 43 3a 5c 57 69 6e 64 6f 77 73 } //1 ((Get-MpPreference).ExclusionPath -contains 'C:\Windows
		$a_81_1 = {28 28 47 65 74 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 29 2e 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e 20 2d 63 6f 6e 74 61 69 6e 73 20 27 65 78 65 27 29 } //2 ((Get-MpPreference).ExclusionExtension -contains 'exe')
		$a_81_2 = {7b 37 30 33 39 33 32 36 31 2d 35 30 44 31 2d 34 38 46 43 2d 38 32 38 32 2d 31 39 32 41 41 37 37 31 45 38 30 38 7d 2e 74 78 74 } //3 {70393261-50D1-48FC-8282-192AA771E808}.txt
		$a_81_3 = {53 79 73 74 65 6d 20 53 65 63 75 72 69 74 79 20 50 75 72 76 69 65 77 } //4 System Security Purview
		$a_81_4 = {6d 69 6e 65 72 5f 6c 6f 67 2e 74 78 74 } //5 miner_log.txt
		$a_81_5 = {73 65 63 72 65 74 6b 65 79 31 32 33 } //6 secretkey123
		$a_81_6 = {57 41 4c 4c 45 54 } //7 WALLET
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6+(#a_81_6  & 1)*7) >=28
 
}