
rule Trojan_Win32_Smokeloader_GMP_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 89 4d ?? 8b 4d ?? d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 8b c8 8b 45 ?? 31 45 ?? 33 4d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 4d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}