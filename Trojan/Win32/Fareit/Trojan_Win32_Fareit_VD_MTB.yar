
rule Trojan_Win32_Fareit_VD_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 03 d0 80 32 90 01 01 40 3d 90 01 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Fareit_VD_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f3 85 d2 90 02 40 8b d6 03 d1 90 02 40 b0 90 02 40 30 02 90 02 40 41 90 00 } //1
		$a_03_1 = {33 d2 f7 f7 85 d2 90 02 40 8b c6 03 c1 90 02 40 30 18 90 02 40 41 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}