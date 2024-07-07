
rule Trojan_Win32_Vidar_NX_MTB{
	meta:
		description = "Trojan:Win32/Vidar.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 2c 89 44 24 1c 8b 44 24 10 01 44 24 1c 8b 44 24 2c c1 e8 90 01 01 89 44 24 14 8b 44 24 14 33 74 24 1c 03 44 24 38 c7 05 90 01 04 ee 3d ea f4 33 c6 83 3d 90 00 } //10
		$a_03_1 = {6a 00 c7 05 90 01 04 64 00 6c 00 c7 05 90 01 04 65 00 6c 00 c7 05 90 01 04 65 00 72 00 66 89 15 90 01 04 a3 90 01 04 ff 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}