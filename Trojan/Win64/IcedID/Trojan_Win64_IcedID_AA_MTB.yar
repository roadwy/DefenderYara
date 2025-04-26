
rule Trojan_Win64_IcedID_AA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c8 2b d1 89 55 ?? 8b 4d ?? 8b 45 ?? 0f af c8 8b 45 ?? 2b c8 01 4d ?? 41 8b cf ff 15 ?? ?? ?? ?? 8b 45 ?? 8d 0c 80 89 4d ?? b9 ?? ?? ?? ?? 8b 45 ?? 2b c8 8b 45 ?? d3 f8 41 8b cf d1 f8 89 45 ?? ff 15 ?? ?? ?? ?? 8b 45 ?? 85 c0 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_IcedID_AA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {41 0f b6 c9 4c 8d ?? ?? ?? 48 8d ?? ?? ?? 8d 41 ?? 83 e1 ?? 83 e0 ?? 48 8d 14 8a 41 8b 0c 80 4d 8d 04 80 41 0f b6 00 83 e1 ?? 02 02 41 32 04 31 41 88 04 19 49 ff c1 8b 02 d3 c8 ff c0 89 02 83 e0 ?? 0f b6 c8 41 8b 00 d3 c8 ff c0 41 89 00 48 8b ?? ?? ?? 4c 3b ?? ?? ?? 73 ?? 48 8b ?? ?? ?? eb } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}
rule Trojan_Win64_IcedID_AA_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af c2 83 e0 01 83 f8 00 41 0f 94 c0 83 f9 0a 41 0f 9c c1 45 88 c2 41 80 f2 ff 45 88 cb 41 80 f3 ff b3 01 80 f3 01 44 88 d6 40 80 e6 ff 41 20 d8 44 88 df 40 80 e7 ff 41 20 d9 44 08 c6 44 08 cf 40 30 fe 45 08 da 41 80 f2 ff 80 cb 01 41 20 da 44 08 d6 40 f6 c6 01 b8 ?? ?? ?? ?? b9 ?? ?? ?? ?? 0f } //1
		$a_03_1 = {88 c2 80 f2 ff 41 88 c8 41 80 f0 ff 41 b1 01 41 80 f1 01 41 88 d2 41 80 e2 ff 44 20 c8 45 88 c3 41 80 e3 ff 44 20 c9 41 08 c2 41 08 cb 45 30 da 44 08 c2 80 f2 ff 41 80 c9 01 44 20 ca 41 08 d2 41 f6 c2 01 be ?? ?? ?? ?? bf ?? ?? ?? ?? 0f } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}