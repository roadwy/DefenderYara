
rule VirTool_Win32_VBInject_OQ_bit{
	meta:
		description = "VirTool:Win32/VBInject.OQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f9 00 75 90 02 20 0f 6e 90 02 20 0f fe 90 02 20 8b 40 2c 90 02 20 0f 6e 90 02 20 0f ef 90 00 } //01 00 
		$a_03_1 = {83 fb 00 75 90 02 20 0f 7e 90 02 40 ff 34 1c 90 02 20 58 90 02 20 e8 90 01 03 00 90 02 20 89 04 1c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}