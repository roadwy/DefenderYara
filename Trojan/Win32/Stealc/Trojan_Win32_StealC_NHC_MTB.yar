
rule Trojan_Win32_StealC_NHC_MTB{
	meta:
		description = "Trojan:Win32/StealC.NHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 45 dc c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 e0 8b 45 dc 31 45 fc 33 55 fc 89 55 dc 8b 45 dc 83 45 f8 64 29 45 f8 83 6d f8 64 83 3d ?? ?? ?? ?? 0c 75 } //1
		$a_03_1 = {8b c2 d3 e8 8d 3c 13 81 c3 ?? ?? ?? ?? 03 45 d4 33 c7 31 45 fc 8b 45 fc 29 45 f0 ff 4d e8 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}