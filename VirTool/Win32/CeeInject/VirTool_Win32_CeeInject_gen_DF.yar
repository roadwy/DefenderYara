
rule VirTool_Win32_CeeInject_gen_DF{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 01 b9 04 00 00 00 b9 90 01 04 39 31 74 90 01 01 8b f0 83 eb 06 8b d8 83 eb 02 83 c0 04 c1 ce 0c 2b d9 90 00 } //01 00 
		$a_01_1 = {c1 c8 09 83 f8 0b 74 14 bb 0e 00 00 00 21 d8 83 eb 08 09 d9 83 c1 01 be 07 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}