
rule Trojan_Win32_Redline_TS_MTB{
	meta:
		description = "Trojan:Win32/Redline.TS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 03 33 4d 90 01 01 89 35 90 01 04 33 cf 89 4d 90 01 01 8b 45 90 01 01 01 05 90 01 04 51 8d 45 90 01 01 50 e8 90 01 04 8b 5d 90 01 01 8b fb c1 e7 90 01 01 81 3d 90 01 08 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_TS_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.TS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c8 88 45 90 01 01 0f b6 4d 90 01 01 31 c0 29 c8 88 45 90 01 01 8b 4d 90 01 01 0f b6 45 90 01 01 31 c8 88 45 90 01 01 0f b6 45 90 01 01 83 e8 90 01 01 88 45 90 01 01 0f b6 45 90 01 01 c1 f8 90 00 } //2
		$a_00_1 = {35 f1 00 00 00 88 45 e3 8a 4d e3 8b 45 e4 88 4c 05 e9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}