
rule Trojan_Win64_CobaltStrike_HND_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 57 69 6e 69 6e 65 74 2e [0-09] c7 84 24 ?? ?? 00 00 64 6c 6c 00 [0-08] ff d7 [0-09] b8 65 74 4f 70 65 6e 41 00 [0-0a] 48 b8 49 6e 74 65 72 6e 65 74 [0-15] ff d6 } //1
		$a_03_1 = {0f b6 c1 0f b6 4c 04 ?? 42 30 8c 04 ?? ?? 00 00 49 ff c0 49 81 f8 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}