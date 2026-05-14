
rule Trojan_Win64_Mint_AB_MTB{
	meta:
		description = "Trojan:Win64/Mint.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {4f 8b 0c e6 47 0f b6 0c 01 4f 8b 14 e7 45 8d 58 05 41 83 e3 0f 47 2a 0c 1a 45 89 c3 41 83 e3 0f 47 32 0c 1a 46 8d 14 01 46 88 0c 17 49 83 c0 01 4c 39 c2 75 cb } //5
		$a_01_1 = {48 0f af c2 4c 01 c0 49 89 c1 49 c1 e9 38 44 30 0c 0f 48 83 c1 01 48 81 f9 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}