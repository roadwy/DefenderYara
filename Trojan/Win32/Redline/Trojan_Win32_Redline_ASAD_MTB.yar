
rule Trojan_Win32_Redline_ASAD_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 75 ec 8b c6 8d 4d f8 e8 [0-04] 8b 45 cc 01 45 f8 8b 45 f4 8b 4d f0 03 c6 31 45 f8 d3 ee 03 75 dc 81 3d [0-04] 21 01 00 00 75 } //1
		$a_03_1 = {d3 ee 03 c7 89 45 d4 c7 05 [0-04] ee 3d ea f4 03 75 e0 8b 45 d4 31 45 f8 33 75 f8 81 3d [0-04] 13 02 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}