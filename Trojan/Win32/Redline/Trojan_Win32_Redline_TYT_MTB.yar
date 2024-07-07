
rule Trojan_Win32_Redline_TYT_MTB{
	meta:
		description = "Trojan:Win32/Redline.TYT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c8 8b d0 c1 ea 90 01 01 03 55 90 01 01 c1 e0 04 03 45 90 01 01 89 4d 90 01 01 33 d0 33 d1 52 8d 45 fc 50 e8 90 00 } //1
		$a_03_1 = {c1 e8 05 03 45 90 01 01 03 f3 33 c6 33 45 90 01 01 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 29 45 08 81 3d 90 01 08 74 90 01 01 68 90 01 04 8d 45 f8 50 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}