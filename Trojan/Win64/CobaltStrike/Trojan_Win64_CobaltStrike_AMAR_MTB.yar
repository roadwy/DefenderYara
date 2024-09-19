
rule Trojan_Win64_CobaltStrike_AMAR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 49 f7 e1 48 89 d0 48 c1 e8 ?? 48 8d 14 ?? 48 8d 04 ?? 48 01 c0 48 89 cb 48 29 c3 0f b6 84 1c ?? ?? ?? ?? 42 32 04 01 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 48 83 c1 01 8b 84 24 ?? ?? ?? ?? 48 39 c8 77 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}