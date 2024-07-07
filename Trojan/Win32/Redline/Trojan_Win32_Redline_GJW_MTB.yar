
rule Trojan_Win32_Redline_GJW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 2f 90 01 01 80 2f 90 01 01 47 e2 90 00 } //10
		$a_03_1 = {d1 fa 0f b6 85 90 01 04 c1 e0 90 01 01 0b d0 88 95 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Redline_GJW_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 74 74 77 6f 79 74 70 6d 64 63 69 71 69 6f 6d 6a 66 6f 73 } //1 gttwoytpmdciqiomjfos
		$a_01_1 = {62 6d 75 61 69 71 6b 6a 67 6c 75 61 72 75 7a 6f } //1 bmuaiqkjgluaruzo
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}