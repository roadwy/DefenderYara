
rule VirTool_Win32_VBInject_gen_HV{
	meta:
		description = "VirTool:Win32/VBInject.gen!HV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 } //01 00  RtlMoveMemory
		$a_03_1 = {8d 4d ec e8 90 01 04 ba 90 01 04 8d 4d ec e8 90 01 04 8d 45 ec 50 68 90 01 04 e8 90 01 04 8b d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}