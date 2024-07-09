
rule Trojan_BAT_CoinMiner_AH_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a 13 08 11 08 11 07 16 73 ?? ?? ?? 0a 13 09 09 8e 69 8d ?? ?? ?? 01 13 0a 11 09 11 0a 16 11 0a 8e 69 6f ?? ?? ?? 0a 13 0b } //4
		$a_01_1 = {5f 35 78 67 33 48 32 48 36 63 46 4e 6a 45 72 43 30 57 65 55 58 70 33 66 4c 4e 30 6d } //1 _5xg3H2H6cFNjErC0WeUXp3fLN0m
		$a_01_2 = {24 64 34 35 61 64 38 30 62 2d 66 35 32 31 2d 34 39 63 34 2d 38 61 65 61 2d 62 66 63 61 32 66 32 31 62 39 62 66 } //1 $d45ad80b-f521-49c4-8aea-bfca2f21b9bf
		$a_01_3 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}