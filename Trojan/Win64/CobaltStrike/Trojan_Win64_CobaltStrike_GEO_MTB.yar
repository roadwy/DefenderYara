
rule Trojan_Win64_CobaltStrike_GEO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 c6 48 c1 ee ?? 48 89 c3 48 c1 eb ?? 4c 21 cb 42 8b 1c 13 41 33 1c b0 48 89 c6 48 c1 ee ?? 4c 21 de 41 33 1c b6 48 8d 72 ?? 4c 21 d8 41 33 1c 87 89 5a 1c 41 ff c4 48 89 fb 48 89 f2 44 3b a1 ?? ?? ?? ?? 0f 82 } //10
		$a_01_1 = {2e 72 65 74 70 6c 6e 65 } //1 .retplne
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}