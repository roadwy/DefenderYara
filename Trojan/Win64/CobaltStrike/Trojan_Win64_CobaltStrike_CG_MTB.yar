
rule Trojan_Win64_CobaltStrike_CG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c3 40 2a c7 24 10 32 03 40 32 c6 88 03 48 03 d9 49 3b dd 72 ?? 8b 44 24 ?? 49 ff c4 49 ff c6 49 ff cf 0f 85 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}
rule Trojan_Win64_CobaltStrike_CG_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 48 c1 e0 ?? 48 01 45 ?? 81 7d ?? ?? ?? ?? ?? 75 ?? 48 8b 45 ?? 8b 00 89 c2 48 8b 45 ?? 48 01 d0 48 ?? ?? ?? 0f b7 45 ?? 83 e8 ?? 66 89 45 ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 66 ?? ?? ?? ?? 0f 85 } //1
		$a_03_1 = {48 89 c1 48 8b 45 ?? 48 8d 50 ?? 48 89 55 ?? 48 89 c2 0f b6 01 88 02 48 8b 45 ?? 48 8d 50 ?? 48 89 55 ?? 48 85 c0 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}