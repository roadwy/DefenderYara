
rule VirTool_Win32_VBInject_ACY_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACY!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 00 10 40 00 [0-20] ad [0-20] 83 f8 00 [0-20] 74 f5 [0-20] 81 38 55 8b ec 83 75 [0-20] 81 78 04 ec 0c 56 8d 75 [0-20] ff 75 3c [0-20] 89 85 c0 00 00 00 [0-20] ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}