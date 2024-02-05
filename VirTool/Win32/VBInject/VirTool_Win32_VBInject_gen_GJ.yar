
rule VirTool_Win32_VBInject_gen_GJ{
	meta:
		description = "VirTool:Win32/VBInject.gen!GJ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f5 58 59 59 59 } //01 00 
		$a_01_1 = {6c 70 fe 6c 64 fe aa 71 9c fd } //01 00 
	condition:
		any of ($a_*)
 
}