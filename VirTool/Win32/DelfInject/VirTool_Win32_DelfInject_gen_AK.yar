
rule VirTool_Win32_DelfInject_gen_AK{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 2e 97 58 4f e8 90 01 03 ff a3 90 01 04 8d 45 e8 50 6a 04 8d 45 e4 50 8b 45 b8 83 c0 08 50 8b 45 f8 50 ff 15 90 01 04 8b 45 e4 89 43 34 8d 45 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}