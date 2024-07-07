
rule Trojan_Win32_Stealc_MB_MTB{
	meta:
		description = "Trojan:Win32/Stealc.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d f0 8b 45 f8 8b 4d f4 03 c7 d3 ef 89 45 ec c7 05 90 01 04 ee 3d ea f4 03 7d 90 01 01 8b 45 ec 31 45 fc 33 7d fc 81 3d 90 01 04 13 02 00 00 75 0b 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}