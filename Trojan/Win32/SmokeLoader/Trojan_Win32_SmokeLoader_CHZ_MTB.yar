
rule Trojan_Win32_SmokeLoader_CHZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 89 4d fc 8b 45 e4 01 45 fc 8b 55 f4 8b 4d f8 8b f2 d3 ee 8d 04 17 31 45 fc 03 75 e0 81 3d ?? ?? ?? ?? 21 01 00 00 75 } //1
		$a_03_1 = {33 c6 2b d8 81 c7 ?? ?? ?? ?? 83 6d ec 01 89 45 fc 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}