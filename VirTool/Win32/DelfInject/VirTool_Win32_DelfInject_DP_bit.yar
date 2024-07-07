
rule VirTool_Win32_DelfInject_DP_bit{
	meta:
		description = "VirTool:Win32/DelfInject.DP!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc e8 90 01 03 ff 8b c8 8b 55 fc a1 90 01 03 00 e8 90 01 03 ff 6a 40 68 00 30 00 00 53 6a 00 e8 90 01 03 ff 8b f0 85 f6 74 70 8b cb 8b d6 8b 45 fc e8 90 01 03 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}