
rule Trojan_Win32_Smokeloader_SPX_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {03 d6 d3 ee 89 55 ec c7 05 70 04 84 00 ee 3d ea f4 03 75 e0 8b 45 ec 31 45 fc 33 75 fc } //00 00 
	condition:
		any of ($a_*)
 
}