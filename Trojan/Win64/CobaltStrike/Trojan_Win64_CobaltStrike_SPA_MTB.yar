
rule Trojan_Win64_CobaltStrike_SPA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 8b cb ff c3 c1 ?? ?? 8b c2 c1 ?? ?? 03 d0 6b ?? ?? [0-10] 0f b6 8c 3a ?? ?? ?? ?? 41 32 4c ?? ?? 43 88 4c 08 ?? 3b 5c 24 20 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}