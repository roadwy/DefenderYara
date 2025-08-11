
rule Trojan_Win64_Midie_AHB_MTB{
	meta:
		description = "Trojan:Win64/Midie.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 03 c8 48 89 4c 24 30 89 44 24 38 0f 28 44 24 30 66 0f 7f 44 24 30 48 8d 85 d0 01 00 00 48 89 44 24 20 4c 8d 8d d8 01 00 00 4c 8d 85 e0 01 00 00 48 8d 95 e8 } //5
		$a_01_1 = {44 8b c0 b8 4f ec c4 4e 41 f7 e8 c1 fa 03 8b ca c1 e9 1f 03 d1 6b ca 1a 44 2b c1 41 8d 50 41 48 8d 4d c0 e8 } //5
		$a_80_2 = {4d 50 33 53 69 6d 57 6e 64 } //MP3SimWnd  5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_80_2  & 1)*5) >=15
 
}