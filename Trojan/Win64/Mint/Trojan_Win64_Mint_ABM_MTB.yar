
rule Trojan_Win64_Mint_ABM_MTB{
	meta:
		description = "Trojan:Win64/Mint.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {4e 8b 34 ca 41 0f b6 2c 1e 4f 8b 34 c8 44 8d 7b ?? 41 83 e7 ?? 43 2a 2c 3e 41 89 df 41 83 e7 ?? 43 32 2c 3e 45 8d 34 1b 42 88 2c 30 48 83 c3 01 48 39 df } //5
		$a_03_1 = {49 0f af c8 4c 01 c9 49 89 ca 49 c1 ea ?? 44 30 14 10 48 83 c2 01 48 81 fa } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}