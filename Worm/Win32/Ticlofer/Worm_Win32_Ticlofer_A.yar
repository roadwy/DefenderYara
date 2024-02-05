
rule Worm_Win32_Ticlofer_A{
	meta:
		description = "Worm:Win32/Ticlofer.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b3 62 8d 45 f4 8b d3 e8 90 01 04 8d 45 f4 ba 90 01 04 e8 90 01 04 8b 45 f4 e8 90 01 04 50 e8 90 01 04 83 f8 02 75 06 c6 45 ff 01 eb 06 43 80 fb 7b 75 ca 90 00 } //01 00 
		$a_03_1 = {84 c0 74 21 bb 02 00 00 00 b8 08 00 00 00 e8 90 01 04 8b 14 85 90 01 04 8d 45 fc e8 90 01 04 4b 75 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}