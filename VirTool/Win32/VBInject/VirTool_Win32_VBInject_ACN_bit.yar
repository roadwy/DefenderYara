
rule VirTool_Win32_VBInject_ACN_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACN!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 59 8b ec 83 [0-30] 4b [0-30] 4b [0-30] 4b [0-30] 4b [0-30] 39 18 75 [0-30] bb ef 0c 56 8d [0-30] 4b [0-30] 4b [0-30] 4b [0-30] 39 58 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}