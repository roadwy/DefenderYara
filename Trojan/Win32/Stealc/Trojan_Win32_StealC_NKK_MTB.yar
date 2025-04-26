
rule Trojan_Win32_StealC_NKK_MTB{
	meta:
		description = "Trojan:Win32/StealC.NKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 45 dc c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 e0 8b 45 dc 31 45 fc 33 55 fc 89 55 dc 8b 45 dc 83 45 f8 ?? 29 45 f8 83 6d f8 64 83 3d ?? ?? ?? ?? 0c 75 } //1
		$a_03_1 = {c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 7d f8 8b 4d f4 8d 04 3b 31 45 fc d3 ef 03 7d d4 81 3d ?? ?? ?? ?? 21 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}