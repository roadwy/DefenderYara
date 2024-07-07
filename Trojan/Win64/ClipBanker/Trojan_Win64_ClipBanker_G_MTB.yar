
rule Trojan_Win64_ClipBanker_G_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 09 00 00 "
		
	strings :
		$a_01_0 = {28 3f 3a 5b 31 33 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 35 2c 33 34 7d 29 73 72 63 5c 6d 61 69 6e 2e 72 73 } //2 (?:[13][a-km-zA-HJ-NP-Z1-9]{25,34})src\main.rs
		$a_01_1 = {44 7b 31 7d 5b 35 2d 39 41 2d 48 4a 2d 4e 50 2d 55 5d 7b 31 7d 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 33 32 7d } //2 D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}
		$a_01_2 = {30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d } //2 0x[a-fA-F0-9]{40}
		$a_01_3 = {5b 4c 4d 33 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 36 2c 33 33 7d } //2 [LM3][a-km-zA-HJ-NP-Z1-9]{26,33}
		$a_01_4 = {5b 34 38 5d 5b 30 2d 39 41 42 5d 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 39 33 7d } //2 [48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}
		$a_01_5 = {58 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 33 33 7d } //2 X[1-9A-HJ-NP-Za-km-z]{33}
		$a_01_6 = {72 5b 30 2d 39 61 2d 7a 41 2d 5a 5d 7b 32 34 2c 33 34 7d } //2 r[0-9a-zA-Z]{24,34}
		$a_01_7 = {6e 6f 74 68 69 6e 67 62 63 31 42 54 43 } //2 nothingbc1BTC
		$a_01_8 = {42 54 43 44 4f 47 45 45 54 43 4c 54 43 58 4d 52 44 41 53 48 52 49 50 50 4c 45 62 6e 62 42 4e 42 61 64 64 72 31 41 44 41 54 54 52 58 74 5a 43 41 53 48 64 65 66 61 75 6c 74 5f 76 61 6c 75 65 5f 63 6c 69 70 70 65 72 5d } //2 BTCDOGEETCLTCXMRDASHRIPPLEbnbBNBaddr1ADATTRXtZCASHdefault_value_clipper]
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=18
 
}