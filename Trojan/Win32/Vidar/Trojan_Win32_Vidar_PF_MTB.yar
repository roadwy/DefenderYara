
rule Trojan_Win32_Vidar_PF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 4d f8 33 4d e0 89 3d 90 01 04 31 4d f4 8b 45 f4 29 45 f0 81 45 dc 90 01 04 83 eb 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}