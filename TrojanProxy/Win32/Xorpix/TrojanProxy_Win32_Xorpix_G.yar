
rule TrojanProxy_Win32_Xorpix_G{
	meta:
		description = "TrojanProxy:Win32/Xorpix.G,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 85 ff fb ff ff 68 01 04 00 00 50 e8 90 01 02 ff ff 8b 45 08 ff 30 5f 8d b5 ff fb ff ff 90 00 } //05 00 
		$a_03_1 = {60 8b 45 08 89 45 fc 8d 45 fc 68 90 01 03 10 6a 00 50 68 90 01 03 10 6a 00 6a 00 e8 90 01 03 00 6a 19 e8 90 01 03 00 8b 45 08 39 45 fc 74 f1 61 ff 75 fc 90 00 } //02 00 
		$a_01_2 = {32 0f 32 1f eb 03 80 e9 20 80 f9 20 73 f8 d3 c3 47 8a 17 0a d2 75 e9 81 f3 } //02 00 
		$a_03_3 = {89 45 fc 68 e1 03 00 00 ff 75 fc 68 90 01 02 00 10 e8 90 01 02 00 00 b8 00 00 00 00 8b 7d fc 8a 07 6a 01 50 68 e0 03 00 00 ff 75 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}