
rule Trojan_Win64_CobaltStrike_LKE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.LKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ed c1 fa 05 8b c2 c1 e8 ?? 03 d0 8b c5 ff c5 6b ?? ?? 2b c2 48 63 c8 48 8b 44 24 38 42 ?? ?? ?? ?? ?? ?? ?? 41 32 ?? ?? 41 88 ?? ?? 49 ?? ?? 3b ?? ?? 30 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}