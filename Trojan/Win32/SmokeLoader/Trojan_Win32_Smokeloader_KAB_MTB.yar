
rule Trojan_Win32_Smokeloader_KAB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 55 f4 8b 4d f8 8b f2 d3 ee 8d 04 13 31 45 fc 03 75 } //00 00 
	condition:
		any of ($a_*)
 
}