
rule Trojan_Win64_CobaltStrike_HLO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b d2 2e 41 8b c0 2b c2 48 63 c8 42 ?? ?? ?? ?? ?? ?? ?? ?? 43 32 94 11 ?? ?? ?? ?? 48 8b 44 24 30 41 88 14 01 41 ff c0 49 ff c1 49 63 c0 48 3b 44 24 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}