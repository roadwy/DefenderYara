
rule VirTool_Win32_Obfuscator_ANS{
	meta:
		description = "VirTool:Win32/Obfuscator.ANS,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 83 c3 01 4e 46 64 8f 03 83 c6 01 83 ee 01 83 c6 01 83 ee 01 4e 46 } //01 00 
		$a_01_1 = {4b 83 c3 01 4b 83 c3 01 4b 83 c3 01 4b 83 c3 01 4e 46 4b 83 c3 01 } //00 00 
	condition:
		any of ($a_*)
 
}