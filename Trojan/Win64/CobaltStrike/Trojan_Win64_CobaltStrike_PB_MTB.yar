
rule Trojan_Win64_CobaltStrike_PB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 1c 05 00 00 ?? 8b 85 1c 05 00 00 3b 85 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_PB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 d0 f7 d0 25 ?? ?? ?? ?? 81 e2 ?? ?? ?? ?? 09 c2 81 f2 ?? ?? ?? ?? 89 15 } //1
		$a_03_1 = {0f b6 09 89 ca f6 d2 89 c3 f6 d3 41 89 d0 41 80 e0 ?? 80 e1 ?? 44 08 c1 08 da 80 e3 ?? 24 ?? 08 d8 30 c8 f6 d2 08 c2 48 8b 45 ?? 88 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}