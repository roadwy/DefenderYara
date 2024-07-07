
rule VirTool_Win32_VBInject_ACJ_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {be 00 10 40 00 ad 83 f8 00 74 90 01 01 bb 54 8b ec 83 43 39 18 75 f0 bb ea 0c 56 8d 43 43 39 58 04 75 90 00 } //1
		$a_01_1 = {31 1c 08 83 e9 fc c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}