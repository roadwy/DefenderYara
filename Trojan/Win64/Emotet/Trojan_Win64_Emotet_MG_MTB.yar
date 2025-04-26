
rule Trojan_Win64_Emotet_MG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c0 41 ff c0 6b d2 ?? 2b c2 48 63 c8 48 8d 05 ?? ?? ?? ?? 8a 04 01 42 32 04 0f 41 88 01 49 ff c1 44 3b c6 72 } //10
		$a_03_1 = {0f b6 04 01 89 44 24 40 8b 44 24 38 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8b 4c 24 28 0f b6 04 01 8b 4c 24 40 33 c8 8b c1 48 63 4c 24 38 48 8b 54 24 30 88 04 0a eb } //10
		$a_03_2 = {f7 ee 03 d6 ff c6 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 48 8d 0d ?? ?? ?? ?? 8a 04 08 41 32 04 2f 41 88 07 49 ff c7 41 3b f6 72 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=10
 
}