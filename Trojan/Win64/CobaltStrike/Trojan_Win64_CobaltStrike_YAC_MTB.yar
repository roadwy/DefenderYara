
rule Trojan_Win64_CobaltStrike_YAC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 43 1c 48 8b 83 ?? ?? ?? ?? 48 63 4b 68 45 8b 04 01 49 83 c1 04 8b 05 ?? ?? ?? ?? 05 db c6 f2 ff 01 03 8b 15 82 32 07 00 8b 83 90 90 00 00 00 81 c2 ?? ?? ?? ?? 03 93 e0 00 00 00 0f af c2 0f b6 53 58 89 83 90 90 00 00 00 41 0f b6 c0 0f af d0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}