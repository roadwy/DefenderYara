
rule Trojan_Win64_ClipBanker_AY_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 35 2c 33 39 7d 24 } //2 (bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$
		$a_01_1 = {28 3f 3a 5e 5b 4c 4d 33 5d 5b 61 2d 6b 6d 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 31 2d 39 5d 7b 32 36 2c 33 33 7d 24 29 } //2 (?:^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$)
		$a_01_2 = {28 3f 3a 5e 30 78 5b 61 2d 66 41 2d 46 30 2d 39 5d 7b 34 30 7d 24 29 } //2 (?:^0x[a-fA-F0-9]{40}$)
		$a_01_3 = {28 3f 3a 5e 5b 34 38 5d 5b 30 2d 39 41 42 5d 5b 31 2d 39 41 2d 48 4a 2d 4e 50 2d 5a 61 2d 6b 6d 2d 7a 5d 7b 39 33 7d 24 29 } //2 (?:^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$)
		$a_01_4 = {28 3f 3a 5e 72 5b 30 2d 39 61 2d 7a 41 2d 5a 5d 7b 33 33 7d 24 29 } //2 (?:^r[0-9a-zA-Z]{33}$)
		$a_01_5 = {53 69 6c 65 6e 74 20 4d 69 6e 65 72 2e 70 64 62 } //2 Silent Miner.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}