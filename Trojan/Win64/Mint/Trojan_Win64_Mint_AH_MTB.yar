
rule Trojan_Win64_Mint_AH_MTB{
	meta:
		description = "Trojan:Win64/Mint.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 33 4c 44 30 8b 44 24 ?? 48 98 66 89 4c 44 30 ff 44 24 ?? 8b 44 24 ?? 83 f8 0a 72 } //30
		$a_03_1 = {8b 44 24 30 8b 44 24 30 8b 4c 24 30 ff 44 24 30 83 c0 ?? 31 c2 8b 44 24 30 85 c0 74 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}