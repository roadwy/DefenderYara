
rule Trojan_Win64_CobaltStrike_R_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 63 c0 48 8d 8d ?? ?? ?? ?? 48 03 c8 0f b6 01 41 88 01 44 88 11 41 0f b6 01 41 03 c2 0f b6 c0 0f b6 8c 05 ?? ?? ?? ?? 41 30 0b 49 ff c3 48 83 eb } //2
		$a_03_1 = {48 8b 4c 24 ?? 8b d1 2b d0 48 c1 e8 ?? 44 8b 44 24 ?? 44 2b c0 8b c2 99 33 c2 2b c2 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}