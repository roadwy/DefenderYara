
rule VirTool_Win32_VBInject_BAZ_bit{
	meta:
		description = "VirTool:Win32/VBInject.BAZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 4f 8b ec 83 90 02 30 83 c3 06 90 02 30 39 18 90 02 30 0f 90 02 30 bb e6 0c 56 8d 90 02 30 83 c3 06 90 02 30 39 58 04 90 02 30 0f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}