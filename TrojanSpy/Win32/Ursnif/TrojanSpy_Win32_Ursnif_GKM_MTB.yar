
rule TrojanSpy_Win32_Ursnif_GKM_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 88 45 90 01 01 8b 15 90 01 04 81 c2 d8 2e 0c 01 89 15 90 01 04 a1 90 01 04 03 45 90 01 01 8b 0d 90 01 04 89 88 90 01 04 0f b6 55 90 01 01 83 ea 07 2b 15 90 01 04 66 89 55 90 01 01 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanSpy_Win32_Ursnif_GKM_MTB_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 68 21 03 01 a3 90 01 04 a1 90 01 04 03 45 90 01 01 8b 0d 90 01 04 89 88 90 01 04 8b 0d 90 01 04 83 e9 14 8b 35 90 01 04 83 de 00 a1 90 01 04 33 d2 03 c8 13 f2 0f b6 45 90 01 01 99 03 c1 13 d6 88 45 90 01 01 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanSpy_Win32_Ursnif_GKM_MTB_3{
	meta:
		description = "TrojanSpy:Win32/Ursnif.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 2b 44 24 90 01 01 03 c6 89 44 24 90 01 01 a3 90 01 04 8b 5c 24 90 01 01 83 44 24 90 01 01 04 89 44 24 90 01 01 8b 44 24 90 01 01 05 b0 93 06 01 89 03 a3 90 01 04 0f b6 c1 6b d8 36 66 a1 90 01 04 02 1d 90 01 04 83 6c 24 90 01 01 01 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanSpy_Win32_Ursnif_GKM_MTB_4{
	meta:
		description = "TrojanSpy:Win32/Ursnif.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 6b c9 34 2a d9 8a ca f6 d8 c0 e1 06 02 ca 2a c1 02 d8 8b 44 24 90 01 01 05 70 80 06 01 a3 90 01 04 89 84 3d 90 01 04 83 c7 04 8b 15 90 01 04 0f b6 c3 66 83 e8 1c 66 03 c2 0f b7 c8 89 4c 24 90 01 01 81 ff 63 19 00 00 73 90 01 01 a1 90 01 04 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}