
rule VirTool_Win32_Obfuscator_QP{
	meta:
		description = "VirTool:Win32/Obfuscator.QP,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 c4 38 c7 45 f4 00 00 00 00 8b 4d 08 0f af 4d 10 03 4d 14 6b c9 0a 3b 4d f4 0f 8e 90 01 04 8b 55 0c 89 95 7c fd ff ff 8d 85 60 fe ff ff 50 8b 0d 90 01 04 51 ff 15 90 01 04 89 85 88 fd ff ff 6a 17 6a 01 8b 95 7c fd ff ff 52 ff 95 88 fd ff ff 90 00 } //02 00 
		$a_00_1 = {89 85 84 fd ff ff 8b 45 f8 50 ff 95 84 fd ff ff 89 85 5c fe ff ff 8b 8d 5c fe ff ff 89 4d f0 8b 55 f0 8b 42 02 83 e8 36 89 45 fc } //00 00 
	condition:
		any of ($a_*)
 
}