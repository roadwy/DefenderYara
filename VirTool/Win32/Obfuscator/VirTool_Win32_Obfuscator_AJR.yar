
rule VirTool_Win32_Obfuscator_AJR{
	meta:
		description = "VirTool:Win32/Obfuscator.AJR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {58 48 50 8b c4 ff 10 90 09 06 00 ff 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}