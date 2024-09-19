
rule Trojan_Win32_Smokeloader_CZS_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d0 8b 44 24 18 c1 e8 05 89 44 24 14 8b 44 24 14 33 ca 03 c5 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 14 0f 85 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}