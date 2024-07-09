
rule Trojan_Win32_Smokeloader_GAM_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 3b 89 4d ?? 8b 4d ?? 8b f7 d3 ee c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 ?? 8b 45 ?? 31 45 ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}