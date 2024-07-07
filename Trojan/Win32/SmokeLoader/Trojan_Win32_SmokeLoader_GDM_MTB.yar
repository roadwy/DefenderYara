
rule Trojan_Win32_SmokeLoader_GDM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {78 36 35 3d 81 6d 90 01 01 db 66 3b 70 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //10
		$a_03_1 = {8b c3 c1 e0 90 01 01 89 5d 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 ff 75 90 01 01 83 0d 90 01 05 8b c3 c1 e8 90 01 01 03 45 90 01 01 c7 05 90 01 04 19 36 6b ff 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}