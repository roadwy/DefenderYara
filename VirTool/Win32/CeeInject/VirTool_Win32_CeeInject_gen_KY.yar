
rule VirTool_Win32_CeeInject_gen_KY{
	meta:
		description = "VirTool:Win32/CeeInject.gen!KY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 c2 ff ff 00 00 03 c8 46 66 85 d2 75 e3 81 f9 5b bc 4a 6a 0f 85 } //1
		$a_03_1 = {8b 4e 28 8b 45 ?? 03 cf 89 88 b0 00 00 00 } //1
		$a_03_2 = {8d 46 34 50 8b 45 ?? 8b 80 a4 00 00 00 83 c0 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}