
rule VirTool_Win32_Obfuscator_OB{
	meta:
		description = "VirTool:Win32/Obfuscator.OB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 33 f6 66 ba 4d 5a 66 ad 66 33 d0 74 08 81 ee 02 10 00 00 eb ed 8d 5e fe 8b 76 3a 66 ba 50 45 8d 34 1e 66 ad 66 33 d0 75 e4 c3 } //00 00 
	condition:
		any of ($a_*)
 
}