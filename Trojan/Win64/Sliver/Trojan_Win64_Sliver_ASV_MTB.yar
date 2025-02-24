
rule Trojan_Win64_Sliver_ASV_MTB{
	meta:
		description = "Trojan:Win64/Sliver.ASV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c1 b9 04 00 00 00 48 6b c9 00 48 8b 54 24 40 89 44 0a 1c 48 8b 44 24 40 48 63 40 4c 48 8b 4c 24 40 48 8b 49 78 0f b6 54 24 64 88 14 01 48 8b 44 24 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Sliver_ASV_MTB_2{
	meta:
		description = "Trojan:Win64/Sliver.ASV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 45 17 e8 ?? ?? ?? ?? 48 8b c8 48 8d 15 65 3f 00 00 e8 ?? ?? ?? ?? 48 8d 4d d7 48 89 45 1f e8 ?? ?? ?? ?? 48 8b c8 48 8d 15 59 3f 00 00 e8 } //2
		$a_03_1 = {c7 45 db 76 00 61 00 c7 45 df 70 00 69 00 c7 45 e3 33 00 32 00 c7 45 e7 2e 00 64 00 c7 45 eb 6c 00 6c 00 e8 ?? ?? ?? ?? 48 8b c8 48 8d 15 8b 3f 00 00 e8 ?? ?? ?? ?? 48 8d 4d d7 48 8b d8 } //1
		$a_03_2 = {57 48 83 ec 20 48 8d 15 6d 3e 00 00 48 8d 0d 6e 3e 00 00 e8 ?? ?? ?? ?? 33 d2 48 8b c8 48 8b f8 44 8d 42 02 e8 ?? ?? ?? ?? 48 8b cf e8 3e 0f 00 00 48 63 d8 45 33 c0 33 d2 48 8b cf 48 8b eb e8 ?? ?? ?? ?? 48 8b cb e8 ?? ?? ?? ?? 4c 8b cf 41 b8 01 00 00 00 48 8b d3 48 8b c8 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*3) >=6
 
}