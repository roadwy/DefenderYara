
rule VirTool_Win32_VBInject_DV{
	meta:
		description = "VirTool:Win32/VBInject.DV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {4a c2 f5 01 00 00 00 aa 90 02 36 fb 12 e7 90 00 } //01 00 
		$a_01_1 = {f5 63 00 00 00 04 40 ff 0a 08 00 08 00 f5 6d 00 00 00 04 2c ff 0a 08 00 08 00 f5 64 00 00 00 04 e4 fe 0a 08 00 08 00 f5 20 } //01 00 
		$a_03_2 = {f3 e8 00 2b 90 01 02 6c 90 01 01 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}