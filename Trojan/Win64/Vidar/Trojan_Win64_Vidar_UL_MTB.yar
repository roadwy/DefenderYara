
rule Trojan_Win64_Vidar_UL_MTB{
	meta:
		description = "Trojan:Win64/Vidar.UL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d6 d3 ea 8d 04 37 89 45 e8 c7 05 a8 a6 61 00 ee 3d ea f4 03 55 dc 8b 45 e8 31 45 fc 33 55 fc 81 3d 10 b1 61 00 13 02 00 00 89 55 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}