
rule Trojan_Win32_Smokeloader_SGOB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SGOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 c1 e8 05 89 45 f8 8b 45 f8 03 45 d4 33 f1 33 c6 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f8 0f 85 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}