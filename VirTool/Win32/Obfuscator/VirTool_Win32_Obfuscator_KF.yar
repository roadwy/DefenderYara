
rule VirTool_Win32_Obfuscator_KF{
	meta:
		description = "VirTool:Win32/Obfuscator.KF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_07_0 = {ba 30 00 00 00 90 17 05 01 01 01 01 05 f8 f9 eb e9 68 90 01 04 c3 90 00 } //01 00 
		$a_07_1 = {a9 00 00 f0 0f 90 17 05 01 01 01 01 05 f8 f9 eb e9 68 90 01 04 c3 90 00 } //01 00 
		$a_07_2 = {a9 00 00 ff 00 90 17 05 01 01 01 01 05 f8 f9 eb e9 68 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}