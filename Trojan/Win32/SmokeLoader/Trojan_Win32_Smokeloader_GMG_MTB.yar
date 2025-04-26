
rule Trojan_Win32_Smokeloader_GMG_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 d3 ef 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d ?? 8b 45 ?? 31 45 ?? 33 7d ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}