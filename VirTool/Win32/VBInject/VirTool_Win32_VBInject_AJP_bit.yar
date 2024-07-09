
rule VirTool_Win32_VBInject_AJP_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJP!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 cb 00 50 40 00 [0-30] 81 eb 00 40 00 00 [0-30] 8b 03 [0-30] bb f4 cb 6c 00 [0-30] 81 c3 59 8e 23 00 } //1
		$a_03_1 = {81 fa 41 41 41 41 90 0a 30 00 5e 90 0a 30 00 33 14 24 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}