
rule Trojan_Win32_Amadey_AHC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 89 4d f0 8b 55 fc 83 ea 01 89 55 fc 83 7d f0 00 76 90 01 01 8b 45 f8 c6 00 00 8b 4d f8 83 c1 01 89 4d f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}