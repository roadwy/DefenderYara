
rule VirTool_Win32_VBInject_AJC_bit{
	meta:
		description = "VirTool:Win32/VBInject.AJC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {bb 59 8b ec 83 4b 4b 4b 4b 39 18 75 ed bb ef 0c 56 8d 4b 4b 4b 39 58 04 75 e0 } //1
		$a_01_1 = {50 49 31 c1 85 c9 75 f9 58 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}