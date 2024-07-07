
rule Trojan_Win32_Dridex_lmnq_MTB{
	meta:
		description = "Trojan:Win32/Dridex.lmnq!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 44 24 48 24 01 0f b6 c8 89 4c 24 40 66 8b 54 24 5e 66 33 54 24 5e 66 89 54 24 5e e9 90 01 04 8b 44 24 44 0f b6 40 04 3d cd 00 00 00 0f 94 c1 80 e1 01 88 4c 24 48 eb c6 0f b6 44 24 1f 8a 4c 24 4a 80 e1 01 88 4c 24 48 83 f8 50 74 d2 eb af 90 00 } //10
		$a_02_1 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 31 c0 31 d2 42 ba 90 01 04 39 d0 77 2d 83 c0 01 83 c0 02 83 e8 02 cc 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}