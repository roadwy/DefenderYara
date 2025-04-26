
rule Trojan_Win64_CobaltStrike_S_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 0f b6 4c 24 ?? 48 8b 54 24 ?? 0f be 04 02 33 c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a } //2
		$a_03_1 = {0f be 00 8b 4c 24 ?? 03 c8 8b c1 89 44 24 ?? 48 8b 44 24 ?? 48 ff c0 48 89 44 24 ?? 48 8b 44 24 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}