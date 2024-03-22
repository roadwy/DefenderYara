
rule Trojan_Win32_Smokeloader_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {33 d2 85 ff 90 01 02 e8 90 01 04 30 04 32 42 3b d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Smokeloader_GZZ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 ff d5 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 e8 90 01 04 30 04 33 46 3b f7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}