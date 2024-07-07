
rule Trojan_Win64_Vidar_PC_MTB{
	meta:
		description = "Trojan:Win64/Vidar.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f7 d3 ee 03 c7 89 45 e0 c7 05 84 39 92 01 ee 3d ea f4 03 75 d0 8b 45 e0 31 45 f8 33 75 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}