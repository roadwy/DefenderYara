
rule Trojan_Win64_CobaltStrike_AN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 63 c1 b8 ?? ?? ?? ?? 45 88 0c 18 41 f7 e1 41 8b c1 c1 ea ?? 41 83 c1 ?? 6b d2 ?? 2b c2 44 3b ce 42 0f b6 04 10 43 88 04 18 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}