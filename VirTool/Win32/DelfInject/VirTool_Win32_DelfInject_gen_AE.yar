
rule VirTool_Win32_DelfInject_gen_AE{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AE,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 0b 00 00 "
		
	strings :
		$a_00_0 = {43 75 72 72 65 6e 74 55 73 65 72 } //1 CurrentUser
		$a_00_1 = {4f 4c 4c 59 44 42 47 } //1 OLLYDBG
		$a_00_2 = {69 63 75 5f 64 62 67 } //2 icu_dbg
		$a_00_3 = {4f 77 6c 57 69 6e 64 6f 77 } //1 OwlWindow
		$a_00_4 = {4f 57 4c 5f 57 69 6e 64 6f 77 } //1 OWL_Window
		$a_00_5 = {54 57 65 6c 63 6f 6d 65 46 6f 72 6d } //1 TWelcomeForm
		$a_00_6 = {64 72 69 76 65 72 73 5c 76 6d 78 6e 65 74 2e 73 79 73 } //2 drivers\vmxnet.sys
		$a_00_7 = {64 ff 30 64 89 20 52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b 59 5a 33 c0 5a 59 59 64 89 10 } //5
		$a_00_8 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b 36 8b 04 24 64 89 05 00 00 00 00 83 c4 08 85 db 0f 94 c0 36 8d 65 fc 36 8b 1c 24 36 8b 6c 24 04 83 c4 08 c3 8b 4c 24 0c c7 81 a4 00 00 00 ff ff ff ff 83 81 } //5
		$a_02_9 = {8b 45 fc 33 db 8a 5c 38 ff 33 5d f8 8d 45 ec 8b d3 e8 ?? ?? ?? ?? 8b 55 ec 8d 45 f0 e8 ?? ?? ?? ?? 47 4e 75 } //5
		$a_03_10 = {44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 80 ea ?? e8 ?? ?? ?? ?? 8b 55 f4 8b c6 e8 ?? ?? ?? ?? 47 4b 75 da 90 09 04 00 8b 45 fc (8a|8b) } //5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*2+(#a_00_7  & 1)*5+(#a_00_8  & 1)*5+(#a_02_9  & 1)*5+(#a_03_10  & 1)*5) >=15
 
}