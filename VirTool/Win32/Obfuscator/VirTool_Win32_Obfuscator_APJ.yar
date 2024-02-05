
rule VirTool_Win32_Obfuscator_APJ{
	meta:
		description = "VirTool:Win32/Obfuscator.APJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 00 00 00 00 31 13 81 3b c3 90 03 03 06 c3 c3 c3 90 90 90 90 90 90 74 90 01 01 83 f8 00 75 90 01 01 31 13 29 c3 90 02 01 31 c0 90 02 01 31 c9 ff 05 90 01 04 eb 90 00 } //01 00 
		$a_03_1 = {31 13 ff 33 90 02 03 8f 05 90 01 04 8b 15 90 01 04 90 02 01 31 13 83 eb 08 3d ac 04 00 00 73 08 83 c0 04 83 c3 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}