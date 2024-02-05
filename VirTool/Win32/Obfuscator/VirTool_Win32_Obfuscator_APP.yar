
rule VirTool_Win32_Obfuscator_APP{
	meta:
		description = "VirTool:Win32/Obfuscator.APP,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 30 8d 01 00 52 f4 80 2d 90 01 04 36 5a 83 25 90 01 05 83 ea 01 75 ea 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}