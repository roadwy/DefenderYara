
rule VirTool_Win32_VBInject_DR{
	meta:
		description = "VirTool:Win32/VBInject.DR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {f5 58 59 59 59 59 90 01 01 ff 6c 90 01 01 ff 90 02 0a f5 04 00 90 00 } //01 00 
		$a_03_1 = {f3 e8 00 2b 90 01 02 6c 90 01 01 ff 90 00 } //01 00 
		$a_03_2 = {80 0c 00 fc 90 90 6c 90 02 0a c2 90 02 08 fc 90 90 fb 11 90 00 } //01 00 
		$a_03_3 = {fb 11 fc f0 6e ff 6c 78 ff f5 90 01 02 00 00 c2 f5 90 01 02 00 00 90 09 02 00 fc 90 90 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}