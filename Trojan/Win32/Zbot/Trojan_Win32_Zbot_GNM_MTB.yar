
rule Trojan_Win32_Zbot_GNM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 5d d0 c1 c3 1c ba c8 41 b6 13 81 c2 90 01 04 23 da b9 65 73 4f 8c 81 f1 90 01 04 b8 00 00 ff ff c1 c0 10 eb 90 01 01 0b da 8b ff 8b e5 5d c2 10 00 90 00 } //10
		$a_01_1 = {8b 13 2b d8 23 d0 4b 3b d1 75 f5 e9 54 02 00 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}