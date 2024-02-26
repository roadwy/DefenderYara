
rule Trojan_Win32_Smokeloader_CCFH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 6a 00 ff 15 90 01 04 8b 44 24 90 01 01 33 c6 89 44 24 90 01 01 8b 44 24 90 01 01 31 44 24 90 01 01 2b 7c 24 90 01 01 81 c3 90 01 04 ff 4c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}