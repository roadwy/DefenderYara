
rule Trojan_Win64_Emotet_DG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 eb 8b cb 03 d3 ff c3 c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1e 2b c8 48 8b 05 [0-04] 48 63 d1 0f b6 0c 02 32 4c 3e ff 88 4f ff 48 83 ed 01 75 } //1
		$a_01_1 = {38 4f 71 58 3e 77 36 2a 42 6f 73 65 55 38 3e 21 32 35 61 41 46 65 6d 76 32 4c 38 4f 78 } //1 8OqX>w6*BoseU8>!25aAFemv2L8Ox
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Emotet_DG_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.DG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 d0 41 8b c4 41 ff c4 6b d2 43 2b c2 48 63 d0 48 63 05 1c a4 06 00 48 0f af c8 48 63 05 21 a4 06 00 48 2b c8 48 8d 04 89 48 03 d0 48 8b 44 24 28 42 0f b6 8c 32 f0 f7 04 00 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72 98 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}