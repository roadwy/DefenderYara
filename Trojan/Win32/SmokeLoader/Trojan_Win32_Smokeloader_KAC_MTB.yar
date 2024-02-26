
rule Trojan_Win32_Smokeloader_KAC_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {03 75 dc 8b 45 ec 31 45 fc 33 75 fc 89 75 d8 8b 45 d8 } //00 00 
	condition:
		any of ($a_*)
 
}