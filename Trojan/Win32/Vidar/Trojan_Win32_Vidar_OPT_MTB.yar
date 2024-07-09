
rule Trojan_Win32_Vidar_OPT_MTB{
	meta:
		description = "Trojan:Win32/Vidar.OPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 89 45 e4 8b 45 ec c1 e8 05 89 45 f8 8b 45 d4 01 45 f8 8b 45 fc c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 e8 89 5d ec 8b 45 ?? 01 45 ec 8b 45 ec 31 45 e8 8b 45 e8 31 45 f8 2b 7d f8 83 3d ?? ?? ?? ?? 0c 89 45 fc 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}