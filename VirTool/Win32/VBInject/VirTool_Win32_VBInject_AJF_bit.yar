
rule VirTool_Win32_VBInject_AJF_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJF!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 10 20 00 [0-30] 81 04 24 00 00 20 00 [0-30] 5b [0-30] 8b 03 } //1
		$a_03_1 = {bb f4 cb 6c 00 [0-30] 81 c3 59 8e 23 00 [0-30] 48 [0-30] 39 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}