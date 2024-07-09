
rule Trojan_Win64_IcedID_AB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 00 89 84 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 4c 24 ?? 33 c8 3a db 74 } //1
		$a_03_1 = {8b c1 48 63 4c 24 ?? 66 3b f6 0f 84 ?? ?? ?? ?? 48 f7 f1 48 8b c2 3a d2 74 ?? 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? ?? 66 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win64_IcedID_AB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 01 89 44 24 68 48 63 4c 24 44 66 ?? ?? 90 13 33 d2 48 8b c1 b9 08 00 00 00 ?? ?? ?? 90 13 48 f7 f1 48 8b c2 48 8b 4c 24 48 3a ?? 90 13 0f b6 44 01 ?? 8b 4c 24 68 33 c8 3a ?? 74 } //1
		$a_03_1 = {0f b6 04 01 89 44 24 68 48 63 4c 24 44 3a ?? 90 13 33 d2 48 8b c1 b9 08 00 00 00 ?? ?? 90 13 48 f7 f1 48 8b c2 48 8b 4c 24 48 66 3b ?? 90 13 0f b6 44 01 ?? 8b 4c 24 68 33 c8 66 3b } //1
		$a_03_2 = {8b c1 48 63 4c 24 44 48 8b 54 24 58 90 13 88 04 0a 90 13 8b 44 24 44 90 13 ff c0 89 44 24 44 8b 84 24 98 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}