
rule VirTool_Win32_VBInject_AID_bit{
	meta:
		description = "VirTool:Win32/VBInject.AID!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 59 00 42 00 [0-30] 48 [0-30] 48 [0-30] 48 [0-30] 39 41 04 [0-30] 0f [0-30] b8 50 00 53 00 [0-30] 48 [0-30] 48 [0-30] 48 [0-30] 39 01 [0-30] 0f [0-30] 59 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}