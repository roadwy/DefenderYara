
rule VirTool_Win32_Vbcrypt_DM{
	meta:
		description = "VirTool:Win32/Vbcrypt.DM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 95 88 fe ff ff 52 8d 85 a8 fe ff ff 50 c7 85 c0 fe ff ff 01 00 00 00 c7 85 b8 fe ff ff 02 00 00 00 c7 85 88 fe ff ff 08 40 00 00 ff 15 } //01 00 
		$a_01_1 = {8d 8d d0 f9 ff ff ff d6 8d 8d cc f9 ff ff ff d6 8d 8d c8 f9 ff ff ff d6 8d 8d c4 f9 ff ff ff d6 8d 8d c0 f9 ff ff ff d6 c3 } //01 00 
		$a_01_2 = {8b 85 8c f7 ff ff c7 85 7c f7 ff ff 03 40 00 00 8b 48 14 c1 e1 04 } //01 00 
		$a_01_3 = {50 6a 10 68 80 08 00 00 ff d3 83 c4 1c b8 02 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}