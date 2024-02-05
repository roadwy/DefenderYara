
rule VirTool_Win32_Obfuscator_AAZ{
	meta:
		description = "VirTool:Win32/Obfuscator.AAZ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {c7 45 ec 38 e1 05 be 68 90 01 04 c7 45 f4 3b e1 05 be ff d7 83 f8 30 0f 8e 39 00 00 00 8b 35 90 01 04 6a 37 ff 35 90 01 04 ff d6 68 90 01 04 ff d7 90 00 } //01 00 
		$a_01_1 = {30 38 39 30 38 39 38 37 00 00 00 00 33 37 36 32 38 37 34 38 32 39 } //00 00 
	condition:
		any of ($a_*)
 
}