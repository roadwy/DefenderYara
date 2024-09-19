
rule Trojan_Win64_CobaltStrike_GLX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GLX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 08 44 31 c2 88 14 08 31 c0 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 29 c8 48 89 44 24 ?? e9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}