
rule Trojan_Win64_CobaltStrike_PF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 03 b8 ?? ?? ?? ?? 41 f7 e1 41 8b c1 c1 ea ?? 41 ff c1 6b d2 ?? 2b c2 8a 4c 18 ?? 41 30 0c 38 48 ff c7 45 3b cb 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}