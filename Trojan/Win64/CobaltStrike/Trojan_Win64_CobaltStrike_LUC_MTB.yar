
rule Trojan_Win64_CobaltStrike_LUC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LUC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c1 48 8b 8c 24 ?? ?? ?? ?? 88 01 0f be 44 24 51 83 e8 33 88 44 24 51 c7 84 24 ?? ?? ?? ?? 2a 7e 00 00 0f b6 44 24 50 05 a0 00 00 00 48 8b 8c 24 80 4f 00 00 88 01 0f b6 44 24 50 35 ef 00 00 00 48 8b 8c 24 ?? ?? ?? ?? 88 01 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}