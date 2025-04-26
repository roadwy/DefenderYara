
rule VirTool_Win32_VBInject_ACO_bit{
	meta:
		description = "VirTool:Win32/VBInject.ACO!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {be 00 10 40 00 31 c0 0b 06 83 c6 04 bb 52 8b ec 83 83 c3 03 39 18 75 ?? bb e9 0c 56 8d 83 c3 03 39 58 04 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}