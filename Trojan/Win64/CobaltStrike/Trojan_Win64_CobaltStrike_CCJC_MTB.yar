
rule Trojan_Win64_CobaltStrike_CCJC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 48 8b 0c 24 0f b6 04 08 0f b6 0d ?? ?? ?? ?? 31 c8 48 98 48 33 04 24 48 8b 4c 24 ?? 48 8b 14 24 88 04 11 48 8b 04 24 48 83 c0 01 48 89 04 24 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}