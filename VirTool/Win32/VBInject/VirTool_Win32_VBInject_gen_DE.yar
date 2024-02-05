
rule VirTool_Win32_VBInject_gen_DE{
	meta:
		description = "VirTool:Win32/VBInject.gen!DE,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {f5 04 00 00 00 f5 58 59 59 59 } //01 00 
		$a_03_1 = {f4 58 fc 0d 90 02 11 f4 59 fc 0d 90 02 11 f4 59 fc 0d 90 02 11 f4 59 fc 0d 90 00 } //02 00 
		$a_03_2 = {f5 40 00 00 00 f5 00 30 00 00 6c 90 01 02 6c 90 01 02 6c 90 01 02 0a 90 00 } //02 00 
		$a_03_3 = {f5 07 00 01 00 71 90 01 02 f5 00 00 00 00 f5 00 00 00 00 04 90 01 02 fe 8e 01 00 00 00 10 00 80 08 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}