
rule Trojan_Win32_Redline_GMS_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c8 0f be 04 bb 33 c1 69 c0 90 01 04 33 f0 8b c6 c1 e8 90 01 01 33 c6 90 00 } //10
		$a_03_1 = {6a 00 ff d6 80 34 2f 90 01 01 6a 00 ff d6 80 04 2f 90 01 01 6a 00 ff d6 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}