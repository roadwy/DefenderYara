
rule Trojan_Win32_Vidar_SB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 03 cf 89 4d f0 8b 4d f4 8b f7 d3 ee c7 05 90 01 04 ee 3d ea f4 03 75 d0 8b 45 f0 31 45 fc 81 3d 90 01 04 e6 09 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}