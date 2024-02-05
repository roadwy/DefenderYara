
rule VirTool_Win32_Obfuscator_VS{
	meta:
		description = "VirTool:Win32/Obfuscator.VS,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_13_0 = {79 73 74 69 63 20 43 6f 6d 70 72 65 73 73 6f 72 00 90 09 05 00 90 03 01 01 e8 e9 90 00 00 } //00 5d 
	condition:
		any of ($a_*)
 
}