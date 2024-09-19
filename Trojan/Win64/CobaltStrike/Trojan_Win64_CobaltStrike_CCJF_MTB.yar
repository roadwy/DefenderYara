
rule Trojan_Win64_CobaltStrike_CCJF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 04 41 59 31 c9 48 89 f2 41 b8 00 30 00 00 ff 15 ?? ?? ?? ?? 48 85 c0 0f 84 ?? ?? ?? ?? 49 89 c7 48 89 c1 48 89 da 49 89 f0 e8 ?? ?? ?? ?? 4c 8d 4d bc 41 c7 01 04 00 00 00 6a 10 41 58 4c 89 f9 48 89 f2 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}