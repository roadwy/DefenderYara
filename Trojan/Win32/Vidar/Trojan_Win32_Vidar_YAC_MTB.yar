
rule Trojan_Win32_Vidar_YAC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d6 33 f7 f7 de 81 c1 f9 5b 85 78 c1 c1 05 f7 de 81 f1 61 da 69 b4 81 c7 fb 85 94 ef 81 31 ?? ?? ?? ?? 33 dc 87 d3 49 } //11
	condition:
		((#a_03_0  & 1)*11) >=11
 
}