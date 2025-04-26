
rule Trojan_Win32_Smokeloader_GMO_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 d3 ee 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 ?? 8b 45 ?? 31 45 ?? 33 75 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}