
rule Trojan_Win32_Smokeloader_GQZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GQZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 cb 8b 85 ?? ?? ?? ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 03 85 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c1 8b 4d ?? 33 c7 2b f0 8b c6 c1 e8 ?? 03 ce } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}