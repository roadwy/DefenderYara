
rule VirTool_Win32_Obfuscator_AQF{
	meta:
		description = "VirTool:Win32/Obfuscator.AQF,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {eb 40 8b 8d 48 fd ff ff 83 c1 52 89 8d 5c fd ff ff 8b 95 f4 fd ff ff 52 8b 85 38 fe ff ff 50 8b 8d 58 ff ff ff } //01 00 
		$a_01_1 = {74 1c 8b 8d 3c ff ff ff 8b 95 20 fe ff ff 8d 84 0a 95 00 00 00 66 89 85 e4 fe ff ff eb 40 } //01 00 
		$a_01_2 = {0f b6 44 24 ef 3c ff 75 02 eb } //01 00 
		$a_01_3 = {8b 8d ec fe ff ff 8d 54 01 3e 66 89 95 dc fe ff ff 8b 45 f0 50 6a 40 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}