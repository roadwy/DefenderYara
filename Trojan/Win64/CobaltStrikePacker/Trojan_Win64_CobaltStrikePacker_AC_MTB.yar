
rule Trojan_Win64_CobaltStrikePacker_AC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikePacker.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 8c 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 90 13 8b 84 24 ?? ?? ?? ?? 83 c0 01 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 39 84 24 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 48 63 84 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 99 b9 ?? ?? ?? ?? f7 f9 8b c2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}