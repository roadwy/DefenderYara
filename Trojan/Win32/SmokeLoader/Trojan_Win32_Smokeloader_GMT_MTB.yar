
rule Trojan_Win32_Smokeloader_GMT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 1f d3 eb 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 5d ?? 8b 45 ?? 31 45 ?? 33 5d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 5d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}