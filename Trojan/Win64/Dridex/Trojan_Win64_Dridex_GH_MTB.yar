
rule Trojan_Win64_Dridex_GH_MTB{
	meta:
		description = "Trojan:Win64/Dridex.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 83 ec 40 8b 44 24 3c 89 ca 09 c2 89 54 24 3c 48 c7 44 24 28 3a 51 d7 3d 4c 8b } //10
		$a_00_1 = {a0 37 b7 8d b9 8f } //1
		$a_00_2 = {9d 51 71 af a7 } //1
		$a_02_3 = {e5 44 15 de 71 f2 89 ?? ?? e6 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=13
 
}
rule Trojan_Win64_Dridex_GH_MTB_2{
	meta:
		description = "Trojan:Win64/Dridex.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {88 d8 41 f6 e2 88 84 24 0d 01 00 00 89 4c 24 ?? 4c 89 c1 44 8b 44 24 ?? e8 ?? ?? ?? ?? 48 8b 8c 24 d0 00 00 00 e8 } //10
		$a_02_1 = {4c 89 f2 44 8b 5c 24 ?? 44 89 44 24 ?? 45 89 d8 8b 6c 24 ?? 44 89 4c 24 ?? 41 89 e9 48 89 7c 24 ?? ff d0 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}