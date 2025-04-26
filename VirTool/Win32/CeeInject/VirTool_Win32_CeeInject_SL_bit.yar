
rule VirTool_Win32_CeeInject_SL_bit{
	meta:
		description = "VirTool:Win32/CeeInject.SL!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {ba c0 15 40 00 83 c4 0c 2b d3 03 d7 89 55 f0 8b 45 f0 33 db 8b d8 ff d3 } //1
		$a_03_1 = {8b fb 6a 04 c1 e7 0f 03 79 0c 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 85 c0 } //1
		$a_01_2 = {57 8b 7c 24 0c 8b d7 2b d1 46 8a 01 88 04 0a 41 4e 75 f7 } //1
		$a_01_3 = {8b d8 8d 45 fc 50 6a 40 8b 73 3c 03 f3 8b 4e 50 8b 56 34 51 52 ff 55 f4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}