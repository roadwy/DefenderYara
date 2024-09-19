
rule Trojan_Win64_CobaltStrike_YI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff c0 89 44 24 ?? 48 63 44 24 ?? 8b 0d ?? ?? ?? ?? 83 c1 ?? 48 63 c9 48 8b 54 24 ?? 48 3b 04 ca 75 } //3
		$a_03_1 = {48 8b 4c 24 ?? 0f b7 04 41 8b 4c 24 ?? 33 c8 8b c1 48 98 48 33 05 ?? ?? ?? ?? 48 25 ?? ?? ?? ?? 48 63 4c 24 ?? 48 2b c1 89 44 24 ?? eb } //5
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*5) >=8
 
}