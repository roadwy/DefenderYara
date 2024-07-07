
rule Trojan_Win32_Redline_DAU_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 83 44 24 14 64 29 44 24 14 83 6c 24 14 64 8b 44 24 14 8d 4c 24 10 e8 90 01 04 8b 44 24 30 01 44 24 10 8b 44 24 14 8b 4c 24 18 8d 14 07 31 54 24 10 d3 e8 03 c3 81 3d 90 01 04 21 01 00 00 8b f8 75 90 00 } //2
		$a_03_1 = {8b 4c 24 18 8b c6 d3 e8 8d 14 37 8b cd 89 54 24 2c 89 44 24 20 8d 44 24 20 c7 05 90 01 04 ee 3d ea f4 e8 90 01 04 8b 44 24 2c 31 44 24 10 81 3d 90 01 04 e6 09 00 00 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}