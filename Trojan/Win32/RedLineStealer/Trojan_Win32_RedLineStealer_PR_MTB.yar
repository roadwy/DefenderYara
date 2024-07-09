
rule Trojan_Win32_RedLineStealer_PR_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 89 44 24 18 8b 44 24 28 01 44 24 18 8b 44 24 14 c1 e8 05 89 44 24 10 8b 44 24 10 33 74 24 18 03 44 24 44 c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c6 } //1
		$a_03_1 = {c1 e1 04 03 4d f0 8b 45 fc 03 45 f8 89 45 0c 8b 45 fc 83 0d ?? ?? ?? ?? ff c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 08 8b 45 e4 01 45 08 8b 45 08 33 45 0c 33 c1 2b f0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}