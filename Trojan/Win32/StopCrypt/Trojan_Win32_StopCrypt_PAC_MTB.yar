
rule Trojan_Win32_StopCrypt_PAC_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 45 fc b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 38 8b 0d 90 01 04 88 04 0f 83 3d 90 01 04 44 75 22 90 00 } //01 00 
		$a_03_1 = {ee 3d ea f4 c7 85 90 01 04 7e 1f 49 08 c7 85 90 01 04 45 9e 40 23 c7 85 90 01 04 a8 84 66 54 c7 85 90 01 04 90 90 8b 37 3f c7 85 90 01 04 dc 73 b8 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}