
rule Trojan_Win32_Redline_GDL_MTB{
	meta:
		description = "Trojan:Win32/Redline.GDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e0 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 83 0d 90 01 04 ff 8b c7 c1 e8 90 01 01 03 45 90 01 01 c7 05 90 01 04 19 36 6b ff 89 45 90 01 01 8b 45 90 01 01 03 c7 90 00 } //10
		$a_03_1 = {8d 4c 24 04 51 90 0a 66 00 c6 05 90 01 04 56 c6 05 90 01 04 63 c6 05 90 01 04 50 c6 05 90 01 04 00 c6 05 90 01 04 74 c6 05 90 01 04 74 c6 05 90 01 04 72 c6 05 90 01 04 72 ff 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}