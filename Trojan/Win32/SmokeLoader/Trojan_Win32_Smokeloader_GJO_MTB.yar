
rule Trojan_Win32_Smokeloader_GJO_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 8b 4c 24 ?? 03 d6 89 54 24 ?? 89 44 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}