
rule Trojan_Win64_PowerLoader_GA_MTB{
	meta:
		description = "Trojan:Win64/PowerLoader.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b d2 41 0f b6 0b 41 8b c0 49 ff c3 48 33 c8 0f b6 c1 41 8b c8 44 8b 04 83 c1 e9 08 44 33 c1 48 ff ca 75 de } //2
		$a_01_1 = {4c 8b f9 48 8d 4c 24 38 45 8d 45 30 33 d2 41 8b f9 41 8b f5 4c 89 6c 24 30 } //1
		$a_01_2 = {41 ff c1 33 d2 41 8b c0 41 f7 f1 30 11 48 ff c1 45 3b ca 72 eb } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}