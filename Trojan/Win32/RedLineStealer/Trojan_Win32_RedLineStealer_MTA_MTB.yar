
rule Trojan_Win32_RedLineStealer_MTA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 04 39 83 3d 90 01 04 44 75 90 0a 1f 00 a1 90 01 04 8a 84 38 3b 2d 0b 00 8b 0d 90 00 } //01 00 
		$a_03_1 = {03 c7 50 89 45 f8 8b c7 c1 e0 04 03 85 90 01 04 50 e8 6a fe ff ff 50 89 85 90 01 04 8b c7 c1 e8 05 03 85 90 01 04 50 8d 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}