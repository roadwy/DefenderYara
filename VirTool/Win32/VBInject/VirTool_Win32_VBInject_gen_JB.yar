
rule VirTool_Win32_VBInject_gen_JB{
	meta:
		description = "VirTool:Win32/VBInject.gen!JB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {f5 3c 00 00 00 aa 59 90 01 02 5e 90 01 03 00 71 90 01 02 f5 02 00 00 00 59 90 01 02 04 90 01 02 5e 90 01 03 00 f5 4d 5a 00 00 c7 f5 04 00 00 00 59 90 01 02 6c 90 01 02 6c 90 01 02 aa 59 90 01 02 5e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}