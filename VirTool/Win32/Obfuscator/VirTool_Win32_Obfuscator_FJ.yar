
rule VirTool_Win32_Obfuscator_FJ{
	meta:
		description = "VirTool:Win32/Obfuscator.FJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 c4 f4 53 57 56 90 90 68 11 10 40 00 90 90 c3 90 90 0f 31 52 90 90 58 83 f8 0a 0f 82 24 00 00 00 90 90 ff 15 90 01 04 52 64 a1 18 00 00 00 8b 40 30 66 8b 80 ac 00 00 00 81 04 24 56 10 40 00 66 29 04 24 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}