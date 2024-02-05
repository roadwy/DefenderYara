
rule VirTool_Win32_Obfuscator_DU{
	meta:
		description = "VirTool:Win32/Obfuscator.DU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c4 08 6a 00 68 90 01 01 3a 5c 90 01 01 54 ff d0 83 c4 08 83 f8 01 75 01 cc 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}