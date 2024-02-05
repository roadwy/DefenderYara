
rule VirTool_Win32_Vbcrypt_DS{
	meta:
		description = "VirTool:Win32/Vbcrypt.DS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 85 b4 fe ff ff c7 85 ac fe ff ff 03 00 00 00 8b 45 c8 89 85 e8 fd ff ff 83 65 c8 00 8b 85 e8 fd ff ff } //01 00 
		$a_01_1 = {83 a5 e4 fe ff ff 00 8b 85 e0 fe ff ff 89 85 b0 fd ff ff 83 a5 e0 fe ff ff 00 8b 85 dc fe ff ff } //01 00 
		$a_01_2 = {83 a5 94 fe ff ff 00 c7 85 8c fe ff ff 02 00 00 00 83 a5 a4 fe ff ff 00 c7 85 9c fe ff ff 02 00 00 00 } //01 00 
		$a_01_3 = {83 65 c8 00 8b 85 ec fd ff ff 89 85 c4 fe ff ff c7 85 bc fe ff ff 08 00 00 00 6a 04 } //01 00 
		$a_03_4 = {8b 7d 08 8d 4d 94 8b 07 51 8d 4d e8 51 68 c2 8c 10 c5 ff 35 90 01 03 00 57 ff 50 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}