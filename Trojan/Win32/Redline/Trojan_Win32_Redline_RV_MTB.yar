
rule Trojan_Win32_Redline_RV_MTB{
	meta:
		description = "Trojan:Win32/Redline.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 8b f7 d3 ee 8d 04 3b 89 45 f0 c7 05 90 01 04 ee 3d ea f4 03 75 d8 8b 45 f0 31 45 fc 81 3d 90 01 04 e6 09 00 00 75 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}