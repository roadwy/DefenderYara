
rule Trojan_Win32_RedLineStealer_MI_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 20 0f 83 06 03 00 00 c7 85 70 ff ff ff 04 00 00 00 8b 55 d0 8b 8d 70 ff ff ff d3 e2 89 55 e4 8b 45 e4 03 45 dc 89 45 e4 8b 45 d0 8b 5d e8 03 c3 89 45 f0 c7 45 a8 05 00 00 00 8b 55 d0 8b 4d a8 d3 ea 89 55 ec 8b 45 ec 03 45 e0 89 45 ec c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 83 3d ?? ?? ?? ?? ?? 75 } //1
		$a_03_1 = {8b 4d e4 33 4d f0 89 4d e4 8b 55 ec 33 55 e4 89 55 ec 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 } //1
		$a_03_2 = {8b 45 f4 8b 4d a8 d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 ec 31 45 e4 8b 45 e4 29 45 d0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? eb ?? 8b 45 e8 2b 45 d8 89 45 e8 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}