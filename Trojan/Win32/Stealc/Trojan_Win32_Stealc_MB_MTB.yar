
rule Trojan_Win32_Stealc_MB_MTB{
	meta:
		description = "Trojan:Win32/Stealc.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 7d f0 8b 45 f8 8b 4d f4 03 c7 d3 ef 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d ?? 8b 45 ec 31 45 fc 33 7d fc 81 3d ?? ?? ?? ?? 13 02 00 00 75 0b } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Stealc_MB_MTB_2{
	meta:
		description = "Trojan:Win32/Stealc.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 1c ff ff ff c1 e8 05 89 45 74 8b 45 74 03 85 14 ff ff ff 8b 95 3c ff ff ff 03 d6 33 c2 33 c1 2b f8 83 3d 6c d2 45 02 0c c7 05 64 d2 45 02 ee 3d ea f4 89 45 74 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}