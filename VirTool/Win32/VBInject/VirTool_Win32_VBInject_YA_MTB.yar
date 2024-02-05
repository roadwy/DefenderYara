
rule VirTool_Win32_VBInject_YA_MTB{
	meta:
		description = "VirTool:Win32/VBInject.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {3b 44 24 10 75 90 01 01 f7 c4 90 01 04 31 c9 f7 c6 90 01 04 66 81 fa 90 01 02 31 34 0f 66 81 fa 90 01 02 83 e9 90 01 01 66 81 fa 90 01 02 81 f9 90 01 02 00 00 75 90 01 01 66 81 fb 90 01 02 57 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}