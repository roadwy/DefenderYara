
rule VirTool_BAT_AsmInject_I{
	meta:
		description = "VirTool:BAT/AsmInject.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6d 70 72 65 73 73 53 68 65 6c 6c } //01 00  CompressShell
		$a_01_1 = {4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 } //01 00  NtSetInformationProcess
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {43 6f 6e 66 75 73 65 72 } //00 00  Confuser
	condition:
		any of ($a_*)
 
}