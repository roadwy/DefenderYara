
rule VirTool_Win32_VBInject_AHH_bit{
	meta:
		description = "VirTool:Win32/VBInject.AHH!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 53 00 42 00 90 02 10 40 90 02 10 40 90 02 10 40 90 02 10 39 41 04 75 90 02 10 68 49 00 53 00 90 02 10 58 90 02 10 40 90 02 10 40 90 02 10 40 90 02 10 40 90 02 10 39 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}