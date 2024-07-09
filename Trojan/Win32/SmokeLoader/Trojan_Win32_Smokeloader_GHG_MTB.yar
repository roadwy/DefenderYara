
rule Trojan_Win32_Smokeloader_GHG_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 8b 4c 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GHG_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 8b 4c 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 2b d9 8b c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}