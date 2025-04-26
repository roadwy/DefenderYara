
rule Trojan_Win32_Smokeloader_GXN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 2a 89 44 24 ?? 8b 44 24 ?? c1 e8 ?? 89 44 24 ?? 8b 4c 24 ?? 8b 44 24 ?? 33 4c 24 ?? 03 44 24 ?? 33 c1 c7 05 ?? ?? ?? ?? ee 3d ea f4 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Smokeloader_GXN_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 33 c1 89 4d ?? 8b 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 81 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}