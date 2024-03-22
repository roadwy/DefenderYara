
rule Trojan_Win32_Smokeloader_GXA_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {03 c8 89 4d 90 01 01 8b 4d 90 01 01 d3 e8 c7 05 90 01 04 ee 3d ea f4 03 c3 50 59 8b 45 90 01 01 31 45 90 01 01 33 4d 90 01 01 81 3d 90 01 08 89 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}