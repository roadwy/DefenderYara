
rule VirTool_Win32_VBInject_BBA_bit{
	meta:
		description = "VirTool:Win32/VBInject.BBA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 00 10 40 00 [0-30] ad [0-30] bb 4f 8b ec 83 [0-30] 83 c3 06 [0-30] 39 18 [0-30] 75 [0-30] bb e6 0c 56 8d [0-30] 83 c3 06 [0-30] 39 58 04 [0-30] 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}