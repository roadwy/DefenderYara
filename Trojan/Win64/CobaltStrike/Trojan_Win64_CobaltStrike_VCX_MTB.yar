
rule Trojan_Win64_CobaltStrike_VCX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.VCX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 89 c0 41 f7 e9 44 89 c0 c1 f8 ?? c1 fa ?? 29 c2 b8 ?? ?? ?? ?? 0f af d0 44 89 c0 29 d0 48 8b 54 24 70 48 98 41 0f b6 04 02 32 04 0a 48 8b 54 24 ?? 88 04 0a 49 8d 48 ?? 48 39 4c 24 ?? 77 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}