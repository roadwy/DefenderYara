
rule Trojan_Win32_SmokeLoader_HGG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.HGG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 45 f0 8b 45 f0 89 45 ec 8b 75 f8 8b 4d f4 d3 ee 03 75 dc 8b 45 ec 31 45 fc 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //1
		$a_03_1 = {33 c6 81 c3 ?? ?? ?? ?? 2b f8 83 6d e0 01 89 45 fc 89 5d e8 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}