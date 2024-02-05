
rule VirTool_Win32_VBInject_gen_CH{
	meta:
		description = "VirTool:Win32/VBInject.gen!CH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c b8 fc 6c 34 fe aa 71 6c fd 00 } //01 00 
		$a_03_1 = {f5 50 45 00 00 cc 1c 90 01 02 00 02 00 1e f5 44 00 00 00 6c 84 fc ae fd 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}