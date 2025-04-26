
rule Trojan_Win32_Redline_HOM_MTB{
	meta:
		description = "Trojan:Win32/Redline.HOM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f0 8b 45 f8 8b f7 d3 ee 03 c7 89 45 e0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 e4 8b 45 e0 31 45 fc 81 3d ?? ?? ?? ?? e6 09 00 00 75 } //1
		$a_03_1 = {8b 45 dc 01 45 fc 8b 45 f4 8b 4d f8 8d 14 01 8b 4d f0 d3 e8 03 45 ?? 33 c2 31 45 fc 2b 7d fc 8b 45 d4 29 45 f8 ff 4d ec 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}