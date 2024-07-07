
rule Trojan_Win32_Redline_HUL_MTB{
	meta:
		description = "Trojan:Win32/Redline.HUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d3 d3 ea 03 c3 89 45 f0 c7 05 90 01 04 ee 3d ea f4 03 55 d8 8b 45 f0 31 45 fc 33 55 fc 81 3d 90 01 04 13 02 00 00 89 55 f0 75 90 00 } //1
		$a_03_1 = {03 c8 89 4d f0 8b 4d f4 d3 e8 03 45 d4 8b c8 8b 45 f0 31 45 fc 31 4d fc 2b 5d fc 8d 45 ec e8 90 01 04 ff 4d e4 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}