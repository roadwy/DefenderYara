
rule VirTool_Win32_Obfuscator_NU{
	meta:
		description = "VirTool:Win32/Obfuscator.NU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 39 83 7d 08 0e 75 07 b8 90 01 03 00 eb 2c 83 7d 08 0f 75 07 b8 90 00 } //01 00 
		$a_03_1 = {52 6a 02 e8 90 01 03 ff 83 c4 04 50 e8 90 01 03 ff 83 c4 04 50 6a 02 e8 90 01 03 ff 83 c4 04 50 e8 90 01 03 00 83 c4 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}