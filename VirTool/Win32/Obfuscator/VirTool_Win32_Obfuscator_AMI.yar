
rule VirTool_Win32_Obfuscator_AMI{
	meta:
		description = "VirTool:Win32/Obfuscator.AMI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d2 83 ec 10 8b 95 90 01 04 8a 8d 90 01 04 2a 8d 90 01 04 8b 52 34 8b b5 90 01 04 03 56 2c 90 00 } //01 00 
		$a_03_1 = {89 4b 10 89 43 0c 89 7b 08 89 73 04 66 8b 85 90 01 04 0f b7 c8 89 0b ff d2 83 ec 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}