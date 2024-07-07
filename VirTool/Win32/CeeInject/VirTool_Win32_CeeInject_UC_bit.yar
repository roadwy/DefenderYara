
rule VirTool_Win32_CeeInject_UC_bit{
	meta:
		description = "VirTool:Win32/CeeInject.UC!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b cf 0f 44 f0 c1 e9 05 03 0d 90 01 04 8b c7 c1 e0 04 03 05 90 01 04 33 c8 8d 04 3e 33 c8 2b d9 8b cb 8b c3 c1 e9 05 03 0d 90 01 04 c1 e0 04 03 05 90 01 04 33 c8 8d 04 1e 33 c8 2b f2 2b f9 90 00 } //1
		$a_03_1 = {05 32 09 00 00 50 6a 00 89 84 24 90 01 01 00 00 00 ff 15 90 01 04 33 f6 a3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}