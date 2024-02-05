
rule VirTool_Win32_Obfuscator_AHR{
	meta:
		description = "VirTool:Win32/Obfuscator.AHR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 c0 48 67 00 00 2b c7 33 c6 0f af c2 33 c1 39 45 f8 0f 82 91 ff ff ff 5b 5f 5e } //00 00 
	condition:
		any of ($a_*)
 
}