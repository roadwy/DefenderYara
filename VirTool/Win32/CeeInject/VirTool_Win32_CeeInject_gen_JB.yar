
rule VirTool_Win32_CeeInject_gen_JB{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 7d c8 10 27 00 00 0f 86 fd 00 00 00 c7 45 c0 ?? ?? ?? ?? ff 75 fc c7 45 bc 00 30 00 00 8b 85 78 ff ff ff 8b 4d ec 89 08 c7 85 50 ff ff ff 00 00 00 00 8f 45 fc ba 20 00 00 00 83 c2 20 b9 00 0b 00 00 52 81 c1 00 05 00 00 8b c1 50 c7 45 fc fb ff 00 00 } //1
		$a_01_1 = {53 43 61 72 64 49 6e 74 72 6f 64 75 63 65 43 61 72 64 54 79 70 65 57 00 57 69 6e 73 63 61 72 64 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}