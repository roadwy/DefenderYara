
rule Trojan_Win32_SmokeLoader_CYC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d6 d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 dc 8b 45 ec 31 45 fc 33 55 fc 89 55 d8 8b 45 d8 83 45 ?? 64 } //1
		$a_03_1 = {8b c2 d3 e8 8b 4d fc 81 c7 47 ?? ?? ?? 89 7d e8 03 45 d0 33 45 ec 33 c8 2b f1 83 eb 01 89 4d fc 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}