
rule Trojan_Win64_CobaltStrike_CM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 c3 0f af d8 f6 c3 01 0f 94 c0 08 c1 89 d3 30 cb 30 c2 30 c1 80 f2 01 08 da 38 d1 0f 85 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_CobaltStrike_CM_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 d3 fa 41 89 d0 0f b6 44 24 ?? 0f b6 d0 0f b6 44 24 ?? 0f b6 c8 b8 ?? ?? ?? ?? 29 c8 89 c1 d3 e2 89 d0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}