
rule Trojan_Win32_Hancitor_GE_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d1 66 89 55 90 01 01 8b 45 90 01 01 05 90 01 04 0f b6 0d 90 01 04 2b c1 03 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 7d 90 01 01 ba 90 01 04 2b d0 ff d7 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Hancitor_GE_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {b3 7e f6 eb b3 3c 2a d8 3b fd 8a c3 75 } //10
		$a_02_1 = {8b 3b 2b f1 83 ee 90 01 01 81 3d 90 01 08 8b ce 75 90 01 01 2b 2d 90 01 04 8d 51 ff 0f af ea 8d 54 01 90 01 01 0f b7 f2 0f b7 f6 81 c7 90 01 04 8b d6 2b 15 90 01 04 89 3b 83 c3 04 83 6c 24 90 01 01 01 89 3d 90 01 04 8d 4c 11 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}