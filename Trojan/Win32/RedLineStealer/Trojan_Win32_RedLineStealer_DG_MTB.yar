
rule Trojan_Win32_RedLineStealer_DG_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ce c1 e1 04 03 4d ec 8b c6 c1 e8 05 03 45 e4 8d 14 33 33 ca 33 c8 2b f9 81 3d ?? ?? ?? ?? 17 04 00 00 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 0c 75 } //1
		$a_03_1 = {8b 55 e8 03 d0 89 55 f4 8b 45 f8 c1 e8 05 89 45 fc 8b 45 fc 33 4d f4 03 45 d4 c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c1 81 3d ?? ?? ?? ?? 16 05 00 00 89 45 fc 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}