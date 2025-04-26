
rule Trojan_Win64_CobaltStrike_YAM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 8b cc 41 b8 ?? ?? ?? ?? 49 8b c2 0f 1f 44 00 00 0f b7 00 41 8b c8 c1 c9 08 41 ff c1 03 c8 41 8b c1 49 03 c2 44 33 c1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}