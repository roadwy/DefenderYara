
rule Trojan_Win32_Smokeloader_MRR_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 14 07 8b 44 24 1c c1 e8 05 89 44 24 14 8b 44 24 14 33 ca 03 c5 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 14 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}