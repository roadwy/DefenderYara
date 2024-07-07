
rule Trojan_Win32_StealC_MVK_MTB{
	meta:
		description = "Trojan:Win32/StealC.MVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea 8d 04 37 89 45 e8 c7 05 90 01 04 ee 3d ea f4 03 55 dc 8b 45 e8 31 45 fc 33 55 fc 81 3d 90 01 04 13 02 00 00 89 55 e8 75 90 00 } //1
		$a_03_1 = {c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 75 f8 8b 4d f4 8d 04 37 31 45 fc d3 ee 03 75 d0 81 3d 90 01 04 21 01 00 00 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}