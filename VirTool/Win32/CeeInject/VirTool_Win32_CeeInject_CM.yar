
rule VirTool_Win32_CeeInject_CM{
	meta:
		description = "VirTool:Win32/CeeInject.CM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 00 e9 83 c4 0c ff 06 8b 06 2b d8 8d 4c 3b fc 89 08 8b 46 04 89 38 8b 46 04 83 c9 ff 2b 08 5f 01 0e 8b c6 5e 5b 5d c2 0c 00 } //1
		$a_09_1 = {53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 } //1 SetThreadContext
		$a_03_2 = {b8 4d 5a 00 00 83 c4 0c 89 35 90 01 03 00 c7 05 90 01 03 00 07 00 01 00 89 1d 90 01 03 00 66 39 03 0f 85 90 01 01 01 00 00 8b 43 3c 03 c3 a3 90 01 03 00 81 38 50 45 00 00 0f 85 90 01 01 01 00 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_09_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}