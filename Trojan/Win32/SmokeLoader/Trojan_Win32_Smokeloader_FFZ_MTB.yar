
rule Trojan_Win32_Smokeloader_FFZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.FFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 c1 ea 05 8d 0c 18 89 55 f8 8b 45 e4 01 45 f8 8b f3 c1 e6 04 03 75 dc 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Smokeloader_FFZ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.FFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 fc 8b 45 fc 03 45 e4 8b 55 f8 03 d6 33 c2 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 fc 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}