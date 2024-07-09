
rule Trojan_Win64_Cobaltstrike_DI_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 3d ?? ?? ?? ?? 77 ?? 8b 85 ?? ?? ?? ?? 48 98 0f b6 44 05 ?? 32 85 ?? ?? ?? ?? 89 c2 8b 85 ?? ?? ?? ?? 48 98 88 54 05 ?? 83 85 ?? ?? ?? ?? ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Cobaltstrike_DI_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 84 24 88 00 00 00 99 b9 04 00 00 00 f7 f9 83 fa 01 41 0f 94 c0 41 80 e0 01 44 88 84 24 94 00 00 00 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 41 89 c9 41 83 e9 01 41 0f af c9 83 e1 01 83 f9 00 41 0f 94 c0 83 fa 0a 41 0f 9c c2 45 08 d0 41 f6 c0 01 b9 26 c4 9f ff ba da ac a6 46 0f 45 d1 89 94 24 80 00 00 00 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}