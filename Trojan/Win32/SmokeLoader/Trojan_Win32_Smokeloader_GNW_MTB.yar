
rule Trojan_Win32_Smokeloader_GNW_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 c1 e8 05 03 44 24 34 81 3d ?? ?? ?? ?? 79 09 00 00 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 20 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GNW_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 3e 89 45 ?? 8b c7 d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GNW_MTB_3{
	meta:
		description = "Trojan:Win32/Smokeloader.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 03 89 4d ?? 8b 4d ?? d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 8b c8 8b 45 ?? 31 45 ?? 33 4d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 4d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}