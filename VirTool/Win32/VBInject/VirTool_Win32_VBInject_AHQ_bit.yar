
rule VirTool_Win32_VBInject_AHQ_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHQ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bf 4d 00 53 00 [0-20] 39 3b 75 [0-20] 81 7b 04 56 00 42 00 75 } //1
		$a_03_1 = {bb 83 ec 8b 55 ?? ?? 39 18 75 [0-10] 81 78 04 ec 0c 56 8d 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}