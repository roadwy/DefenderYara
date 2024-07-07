
rule Trojan_Win32_Gozi_GS_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 d5 00 0f b6 0d 90 01 04 8b 15 90 01 04 8b 3d 90 01 04 8d 4c 11 05 89 0d 90 01 04 8b 8c 37 90 01 04 81 c1 90 01 04 89 0d 90 01 04 89 8c 37 90 01 04 8b 15 90 01 04 8a ca 83 c6 04 80 c1 90 01 01 81 fe 90 01 04 0f 82 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GS_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 66 01 35 90 01 04 89 44 24 90 01 01 a3 90 01 04 8b 54 24 90 01 01 83 44 24 90 01 01 04 8b 02 05 90 01 04 89 02 8b 15 90 01 04 a3 90 01 04 8d 04 49 03 c0 8b cb 2b c8 0f af ce 2b ca 83 6c 24 90 01 01 01 0f b7 f1 8b 4c 24 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GS_MTB_3{
	meta:
		description = "Trojan:Win32/Gozi.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 8d 52 01 a3 90 02 04 8a 44 17 ff 88 42 ff 8b 35 90 02 04 8d 46 90 01 01 03 c5 89 44 24 90 01 01 85 c9 75 90 00 } //10
		$a_02_1 = {2b c8 2b ce 89 0d 90 02 04 8b 0d 90 02 04 8b 84 11 90 02 04 05 90 02 04 a3 90 02 04 89 84 11 90 02 04 83 c2 04 a1 90 02 04 8b 35 90 02 04 83 c0 90 01 01 03 c6 a3 90 02 04 81 fa 90 02 04 72 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}