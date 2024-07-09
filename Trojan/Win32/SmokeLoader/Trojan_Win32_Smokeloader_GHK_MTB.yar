
rule Trojan_Win32_Smokeloader_GHK_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ee 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 74 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 2b f9 8b c7 8d 4c 24 ?? 89 7c 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}