
rule Trojan_Win32_Smokeloader_GXN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 c7 89 45 90 01 01 8b 45 90 01 01 c1 e8 90 01 01 89 45 90 01 01 8b 4d 90 01 01 33 4d 90 01 01 8b 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 33 c1 89 4d 90 01 01 8b 0d 90 01 04 c7 05 90 01 04 ee 3d ea f4 89 45 90 01 01 81 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}