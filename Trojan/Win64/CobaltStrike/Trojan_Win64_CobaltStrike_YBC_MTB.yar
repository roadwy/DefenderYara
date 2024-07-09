
rule Trojan_Win64_CobaltStrike_YBC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 f1 48 8b c2 0f b6 44 04 ?? 48 8b 4c 24 48 48 8b 54 24 60 0f b6 0c 11 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 48 88 04 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}