
rule VirTool_Win32_VBInject_ACD_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 53 8b ec 83 [0-30] 83 c3 02 [0-30] 39 18 75 [0-30] bb ea 0c 56 8d [0-30] 83 c3 02 [0-30] 39 58 04 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}