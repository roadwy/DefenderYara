
rule Trojan_Win64_CobaltStrike_GKZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 0f b6 44 05 ?? 83 f0 41 89 c2 8b 85 ?? ?? ?? ?? 48 98 88 54 05 ?? 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 48 98 48 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}