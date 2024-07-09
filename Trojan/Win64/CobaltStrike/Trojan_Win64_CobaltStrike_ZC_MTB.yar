
rule Trojan_Win64_CobaltStrike_ZC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 85 db 0f 84 ?? ?? ?? ?? 41 50 41 54 49 c7 c4 00 00 00 00 4d 89 e0 41 5c 49 01 c0 41 54 49 c7 c4 00 00 00 00 4d 01 c4 49 01 0c 24 41 5c ff 34 24 41 58 48 81 c4 ?? ?? ?? ?? 48 83 c0 ?? 83 eb 01 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_ZC_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 89 8c 24 ?? ?? ?? ?? 8a 54 34 ?? 0f b6 44 0c ?? 88 44 34 ?? 88 54 0c ?? 8b 94 24 ?? ?? ?? ?? 8b b4 24 ?? ?? ?? ?? 0f b6 4c 14 ?? 0f b6 44 34 ?? 03 c8 0f b6 c1 8b 4c 24 ?? 0f b6 44 04 ?? 30 04 19 41 89 4c 24 ?? 3b cf 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}