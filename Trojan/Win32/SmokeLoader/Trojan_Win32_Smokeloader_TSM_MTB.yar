
rule Trojan_Win32_Smokeloader_TSM_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.TSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 c1 e8 05 89 45 f4 8b 45 f4 03 45 dc 33 ca 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f4 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}