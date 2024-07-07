
rule VirTool_Win32_CeeInject_gen_DD{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d0 c0 32 c8 d0 c0 32 c8 d0 c0 32 c8 d0 c0 c1 ea 02 32 82 90 01 04 32 c1 34 90 01 01 88 45 ff 84 db 74 90 01 01 b0 01 32 d2 90 00 } //1
		$a_01_1 = {f6 eb 88 45 f4 8a 46 02 c0 e8 05 88 45 fb 24 04 f6 eb 88 45 f5 8a 46 02 c0 e8 06 88 45 e9 24 02 f6 eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}