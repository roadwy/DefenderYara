
rule Trojan_Win32_Smokeloader_GNA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 d6 d3 ee 8b cd 8d 44 24 90 01 01 89 54 24 90 01 01 89 74 24 90 01 01 c7 05 90 01 04 ee 3d ea f4 e8 90 01 04 8b 44 24 90 01 01 31 44 24 90 01 01 81 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}