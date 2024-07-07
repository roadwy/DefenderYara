
rule Trojan_Win32_StealC_RYY_MTB{
	meta:
		description = "Trojan:Win32/StealC.RYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ef 89 45 f0 c7 05 90 01 04 ee 3d ea f4 03 7d e4 8b 45 f0 31 45 fc 33 7d fc 81 3d 90 01 04 13 02 00 00 89 7d f0 75 90 00 } //1
		$a_03_1 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 7d f4 8b 4d f8 8d 04 3b 31 45 fc d3 ef 03 7d e0 81 3d 90 01 04 21 01 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}