
rule Trojan_Win32_Gozi_GO_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 6b c9 90 01 01 2a d9 8a ca f6 d8 c0 e1 90 01 01 02 ca 2a c1 02 d8 8b 44 24 90 01 01 05 90 01 04 a3 90 01 04 89 84 3d 90 01 04 83 c7 90 01 01 8b 15 90 01 04 0f b6 c3 66 83 e8 90 01 01 66 03 c2 0f b7 c8 89 4c 24 90 01 01 81 ff 90 01 04 73 90 01 01 a1 90 01 04 e9 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Gozi_GO_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 08 88 0a 8b 55 90 01 01 83 c2 01 89 55 90 01 01 8b 45 90 01 01 83 c0 01 89 45 90 01 01 8b 4d 90 01 01 83 c1 90 01 01 8b 75 90 01 01 83 d6 00 33 d2 2b 4d 90 01 01 1b f2 0f b7 45 90 01 01 99 2b c1 1b d6 66 89 45 90 01 01 eb 90 00 } //10
		$a_02_1 = {0f b6 45 ff 83 e8 90 01 01 2b 05 90 01 04 66 89 45 90 01 01 8b 0d 90 01 04 81 c1 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 55 f4 a1 90 01 04 89 82 90 01 04 0f b7 4d 90 01 01 8b 15 90 01 04 8d 84 0a 90 01 04 66 89 45 90 01 01 e9 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}