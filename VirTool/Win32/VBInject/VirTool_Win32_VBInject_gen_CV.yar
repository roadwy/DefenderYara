
rule VirTool_Win32_VBInject_gen_CV{
	meta:
		description = "VirTool:Win32/VBInject.gen!CV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {94 88 fc 1c 00 94 88 fc 10 00 aa 71 9c fd } //01 00 
		$a_01_1 = {94 0c fc 1c 00 94 0c fc 10 00 aa 71 60 fd } //02 00 
		$a_01_2 = {6c 74 ff ae f5 05 00 00 00 ae 71 74 ff } //01 00 
	condition:
		any of ($a_*)
 
}