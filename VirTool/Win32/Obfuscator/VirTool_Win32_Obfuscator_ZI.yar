
rule VirTool_Win32_Obfuscator_ZI{
	meta:
		description = "VirTool:Win32/Obfuscator.ZI,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {a0 40 00 81 05 f4 ac 40 00 00 c0 00 00 8d 90 01 01 dc 90 00 } //01 00 
		$a_03_1 = {60 ae 0a 00 0f 82 90 01 01 ff ff ff ff 90 03 01 01 15 35 f4 ac 40 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}