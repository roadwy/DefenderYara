
rule VirTool_Win32_VBInject_VJ_bit{
	meta:
		description = "VirTool:Win32/VBInject.VJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 00 41 00 33 00 30 00 35 00 45 00 36 00 34 00 41 00 44 00 38 00 42 00 34 00 30 00 31 00 30 00 38 00 42 00 37 00 30 00 33 00 43 00 30 00 46 00 42 00 37 00 34 00 38 00 33 00 38 00 38 00 42 00 37 00 43 00 32 00 34 00 30 00 34 00 38 00 39 00 34 00 46 00 46 00 43 00 46 00 33 00 41 00 34 00 43 00 33 00 } //00 00 
	condition:
		any of ($a_*)
 
}