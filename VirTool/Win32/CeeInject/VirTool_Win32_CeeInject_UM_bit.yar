
rule VirTool_Win32_CeeInject_UM_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 fe e6 26 00 00 7d 07 53 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 37 83 ee 01 79 e4 } //1
		$a_03_1 = {0f b6 c2 03 c8 0f b6 c1 5e 8a 80 90 09 07 00 0f b6 8e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}