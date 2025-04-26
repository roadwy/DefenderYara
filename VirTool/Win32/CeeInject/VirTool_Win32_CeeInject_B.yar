
rule VirTool_Win32_CeeInject_B{
	meta:
		description = "VirTool:Win32/CeeInject.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 81 3f 4d 5a c7 44 24 20 44 00 00 00 c7 44 24 68 07 00 01 00 0f 85 ?? ?? 00 00 8b 77 3c 03 f7 81 3e 50 45 00 00 0f 85 } //1
		$a_01_1 = {0f b6 51 01 8a 59 ff 8a 01 88 54 24 0a 0f b6 51 02 88 54 24 0b 8b d6 81 e2 03 00 00 80 79 05 4a 83 ca fc 42 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}