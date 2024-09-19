
rule Trojan_Win32_Smokeloader_GNX_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d6 33 c2 33 c1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}