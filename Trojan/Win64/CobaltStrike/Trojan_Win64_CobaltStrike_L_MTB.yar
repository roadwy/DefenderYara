
rule Trojan_Win64_CobaltStrike_L_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 41 ff c0 48 8b 84 24 ?? ?? ?? ?? 42 0f b6 14 11 41 32 14 19 41 88 14 01 49 ff c1 44 3b 84 24 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}