
rule Worm_Win32_Nokpuda_A{
	meta:
		description = "Worm:Win32/Nokpuda.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 5c 10 ff 8b c3 83 c0 e0 83 e8 5b 73 1f b8 5a 00 00 00 e8 90 01 04 f7 6d f4 03 d8 83 fb 20 7c 05 83 fb 7a 7e 06 6b 45 f4 5a 90 00 } //01 00 
		$a_03_1 = {b3 43 8d 85 28 fe ff ff 8b d3 e8 90 01 04 8d 85 28 fe ff ff ba 90 01 04 e8 90 01 04 8b 85 28 fe ff ff e8 90 01 04 50 e8 90 01 04 83 f8 90 03 01 01 02 04 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}