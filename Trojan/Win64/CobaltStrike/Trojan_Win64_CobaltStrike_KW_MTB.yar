
rule Trojan_Win64_CobaltStrike_KW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.KW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 25 03 ?? ?? ?? 7d ?? ff c8 83 c8 ?? ff c0 48 63 c8 ff c2 0f b6 44 0c ?? 32 03 41 88 84 18 ?? ?? ?? ?? 48 ff c3 41 3b d7 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}