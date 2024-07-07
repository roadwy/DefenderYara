
rule VirTool_Win32_VBInject_ADP_bit{
	meta:
		description = "VirTool:Win32/VBInject.ADP!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 00 10 40 00 85 d8 ad 90 02 10 83 f8 00 74 f5 90 02 10 bb 56 8b ec 83 85 d8 4b 90 02 10 39 18 75 e5 90 02 10 81 78 04 ec 0c 56 8d 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}