
rule Trojan_Win32_Amadey_MYC_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f3 c1 ee 90 01 01 03 74 24 90 01 01 81 3d 90 01 08 75 90 01 01 ff 15 90 01 04 8b 44 24 90 01 01 33 c6 89 44 24 90 01 01 50 8b c7 e8 90 01 04 81 44 24 90 01 05 83 6c 24 90 01 02 8b f8 89 7c 24 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}