
rule VirTool_Win32_CeeInject_gen_EF{
	meta:
		description = "VirTool:Win32/CeeInject.gen!EF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {40 42 0f 00 75 90 01 01 8b 95 90 01 02 ff ff 8b 02 90 09 05 00 dd d8 90 01 01 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}