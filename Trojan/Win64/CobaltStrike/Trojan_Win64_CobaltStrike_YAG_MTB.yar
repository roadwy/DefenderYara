
rule Trojan_Win64_CobaltStrike_YAG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 00 04 00 00 0f ba f8 0a 41 88 04 24 49 ff c4 49 83 ff 10 72 31 49 8d 57 01 48 8b c3 48 81 fa 00 10 00 00 72 19 48 83 c2 27 48 8b 5b f8 48 2b c3 48 83 c0 f8 48 83 f8 1f 0f 87 ?? ?? ?? ?? 48 8b cb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_YAG_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 d0 c1 c2 08 e9 ce a4 01 00 e9 } //10
		$a_03_1 = {48 c7 04 24 65 00 00 00 90 13 48 ?? ?? ?? ?? 78 00 00 00 48 ?? ?? ?? ?? 70 00 00 00 48 ?? ?? ?? ?? 6c 00 00 00 90 13 48 ?? ?? ?? ?? 6f 00 00 00 48 ?? ?? ?? ?? 72 00 00 00 48 c7 44 24 06 65 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}