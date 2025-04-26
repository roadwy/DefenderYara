
rule Trojan_Win32_SmokeLoader_GLM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 45 ec 8b 45 ec 89 45 f0 8b 75 f8 8b 4d f4 8b 55 f0 31 55 fc d3 ee 03 75 d4 81 3d ?? ?? ?? ?? 21 01 00 00 75 } //1
		$a_03_1 = {33 c6 81 c3 47 86 c8 61 2b f8 83 6d e4 ?? 89 45 fc 89 5d e8 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}