
rule VirTool_Win32_Injector_gen_CB{
	meta:
		description = "VirTool:Win32/Injector.gen!CB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff b5 90 01 02 ff ff ff d0 90 00 } //01 00 
		$a_03_1 = {6a 04 68 00 10 00 00 6a 04 53 ff d0 8b f8 89 bd 90 01 01 ff ff ff c7 07 07 00 01 00 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}