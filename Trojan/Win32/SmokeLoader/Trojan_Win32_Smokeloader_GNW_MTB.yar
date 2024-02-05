
rule Trojan_Win32_Smokeloader_GNW_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8d 04 3e 89 45 90 01 01 8b c7 d3 e8 8b 4d 90 01 01 c7 05 90 01 04 ee 3d ea f4 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 31 45 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}