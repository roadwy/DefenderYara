
rule Trojan_Win32_Amadey_AMY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 2b c6 57 3b f8 77 90 01 01 8d 04 3e 83 fb 10 89 85 90 01 04 8d 85 90 01 04 0f 43 85 90 01 04 03 f0 8d 85 90 01 04 50 56 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}