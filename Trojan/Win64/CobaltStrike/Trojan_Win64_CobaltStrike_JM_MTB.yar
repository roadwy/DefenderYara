
rule Trojan_Win64_CobaltStrike_JM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 49 f7 e0 48 c1 ea ?? 48 8d 04 52 48 8d 04 82 48 01 c0 48 89 ca 48 29 c2 0f b6 84 14 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 32 04 0a 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 48 83 c1 ?? 48 39 8c 24 ?? ?? ?? ?? 77 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}