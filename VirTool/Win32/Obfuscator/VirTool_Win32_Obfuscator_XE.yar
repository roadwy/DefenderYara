
rule VirTool_Win32_Obfuscator_XE{
	meta:
		description = "VirTool:Win32/Obfuscator.XE,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {66 81 7c 24 10 dc 07 74 } //01 00 
		$a_03_1 = {81 fb 60 ae 0a 00 89 90 02 05 0f 82 90 01 01 fe ff ff 8b 1d 90 03 01 01 5c 7c bb 40 00 ff d3 6a 00 ff 15 90 01 01 80 40 00 90 00 } //01 00 
		$a_03_2 = {60 ae 0a 00 0f 82 90 01 02 ff ff 8b 1d 7c bb 40 00 ff d3 6a 00 ff 15 90 01 01 80 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}