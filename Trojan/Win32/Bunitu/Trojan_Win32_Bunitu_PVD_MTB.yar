
rule Trojan_Win32_Bunitu_PVD_MTB{
	meta:
		description = "Trojan:Win32/Bunitu.PVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b d7 8b ca b8 ff 01 00 00 03 c1 2d ff 01 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 } //2
		$a_02_1 = {83 e8 01 33 c9 03 45 e8 13 4d ec 89 45 e4 8b 15 ?? ?? ?? ?? 81 c2 34 76 1a 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 e0 8b 0d ?? ?? ?? ?? 89 88 85 f8 ff ff 90 09 05 00 a1 } //2
		$a_02_2 = {8b 45 fc 33 45 f8 89 45 fc 8b 45 f4 2b 45 fc 89 45 f4 8b 45 e8 2b 45 c8 89 45 e8 c7 05 ?? ?? ?? ?? ca e3 40 df e9 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2) >=2
 
}