
rule VirTool_Win32_Injector_ID_bit{
	meta:
		description = "VirTool:Win32/Injector.ID!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 5c 24 90 01 01 0f be 7c 24 90 01 01 31 fb 8b 7c 24 90 01 01 31 fb 33 5c 24 90 01 01 8b 7c 24 90 01 01 31 fb 89 d8 88 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}