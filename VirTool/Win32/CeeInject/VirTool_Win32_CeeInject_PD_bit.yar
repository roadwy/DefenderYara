
rule VirTool_Win32_CeeInject_PD_bit{
	meta:
		description = "VirTool:Win32/CeeInject.PD!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 06 83 c6 90 01 01 03 05 90 01 04 33 05 90 01 04 c1 c0 90 01 0d c1 c0 90 01 0d c1 c0 90 01 01 2b 05 90 01 04 c1 c0 90 01 01 c1 0d 90 01 05 ab 81 fe 90 01 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}