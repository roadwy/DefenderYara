
rule Trojan_Win32_Fragtor_FL_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.FL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d0 66 81 e2 ff 03 0f b7 d2 89 15 48 97 48 00 0f b7 c0 c1 e8 0a a3 4c 97 48 00 be e0 d2 40 00 bf 0c 61 48 00 b9 08 00 00 00 f3 a5 83 3d c4 60 48 00 02 0f 85 a7 00 00 00 } //10
		$a_01_1 = {32 33 00 00 00 00 6f 39 32 32 00 00 00 00 55 8b ec 83 c4 f8 89 55 f8 89 45 fc 33 c0 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}