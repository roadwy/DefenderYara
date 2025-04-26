
rule VirTool_Win32_VBInject_AGU_bit{
	meta:
		description = "VirTool:Win32/VBInject.AGU!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 6e 5c 24 0c [0-20] 0f ef d9 [0-20] 0f 7e d9 [0-20] 81 f9 00 00 04 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule VirTool_Win32_VBInject_AGU_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AGU!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 55 00 42 00 [0-20] 40 [0-20] 39 41 04 [0-20] b8 4b 00 53 00 [0-20] 40 [0-20] 40 [0-20] 39 01 [0-20] 59 [0-20] 8b 73 10 [0-20] 89 f7 [0-20] 8b 5e 3c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}