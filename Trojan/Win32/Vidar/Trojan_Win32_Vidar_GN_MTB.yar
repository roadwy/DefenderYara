
rule Trojan_Win32_Vidar_GN_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 55 f4 8b 4d f8 8b f2 d3 ee 8d 04 13 31 45 fc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}