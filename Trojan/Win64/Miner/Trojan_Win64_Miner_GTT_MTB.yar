
rule Trojan_Win64_Miner_GTT_MTB{
	meta:
		description = "Trojan:Win64/Miner.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 0f af f0 4d 01 f7 4c 89 f8 50 58 48 89 45 ?? 4c 63 7d ?? 48 63 8c 24 ?? 01 00 00 49 29 cf 4c 89 f8 50 58 89 45 ?? 48 c7 c0 80 00 00 00 48 89 c0 50 48 63 45 ?? 50 59 5a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}