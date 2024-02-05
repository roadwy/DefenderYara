
rule VirTool_Win32_Injector_IF{
	meta:
		description = "VirTool:Win32/Injector.IF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 0b b9 8e 00 00 00 58 ba 80 00 00 00 6a 04 } //01 00 
		$a_01_1 = {81 7d ec 13 7b 83 12 7f 41 8b 45 ec 40 } //00 00 
	condition:
		any of ($a_*)
 
}