
rule Trojan_Win32_SmokeLoader_NEAB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f4 8b c8 03 d0 c1 e1 04 03 4d e8 c1 e8 05 89 55 0c 89 45 08 8b 45 e4 01 45 08 8b 45 08 33 45 0c 33 d2 33 c1 50 89 45 08 8d 45 f8 50 } //10
		$a_03_1 = {89 45 08 8b 45 ec 01 45 08 03 f3 33 75 08 33 75 0c 89 75 e0 8b 45 e0 29 45 fc 81 45 f4 ?? ?? ?? ?? ff 4d f0 8b 45 fc 0f 85 ?? ?? ?? ?? 89 07 89 4f 04 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}