
rule Trojan_Win32_Smokeloader_PBV_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.PBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 cf 8b 45 f0 c1 e8 05 89 45 fc 8b 55 dc 01 55 fc 33 f1 81 3d ?? ?? ?? ?? e6 09 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}