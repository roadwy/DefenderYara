
rule Trojan_Win32_Antavmu_GFS_MTB{
	meta:
		description = "Trojan:Win32/Antavmu.GFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 74 24 58 8b 4f 54 55 8b 7e 3c 03 cf 8b f8 8b d1 c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8b 4c 24 5c } //10
		$a_01_1 = {8b d8 8b 44 24 48 33 d2 83 c4 0c 8b 48 04 8b 00 89 4c 24 0c c7 44 24 08 00 00 00 00 66 8b 50 14 66 83 78 06 00 8d 6c 02 18 0f 86 99 00 00 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}