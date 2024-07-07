
rule VirTool_Win32_DelfInject_gen_D{
	meta:
		description = "VirTool:Win32/DelfInject.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 } //1 RtlDecompressBuffer
		$a_01_1 = {89 45 e4 c7 45 f0 01 00 00 00 8b 45 fc 8b 55 f0 0f b6 44 10 ff } //1
		$a_00_2 = {64 ff 30 64 89 20 52 51 53 b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff 5b 59 5a 33 c0 5a 59 59 64 89 10 } //3
		$a_00_3 = {64 ff 35 00 00 00 00 64 89 25 00 00 00 00 bb 00 00 00 00 b8 01 00 00 00 0f 3f 07 0b 36 8b 04 24 64 89 05 00 00 00 00 83 c4 08 85 db 0f 94 c0 36 8d 65 fc 36 8b 1c 24 36 8b 6c 24 04 83 c4 08 c3 8b 4c 24 0c c7 81 a4 00 00 00 ff ff ff ff 83 81 } //3
		$a_00_4 = {ff ff ff ff 07 00 00 00 73 61 6e 64 62 6f 78 00 ff ff ff ff 05 00 00 00 68 6f 6e 65 79 00 00 00 ff ff ff ff 06 00 00 00 76 6d 77 61 72 65 00 00 ff ff ff ff 0b 00 00 00 63 75 72 72 65 6e 74 75 73 65 72 00 ff ff ff ff 09 00 00 00 6e 65 70 65 6e 74 68 65 73 } //5
		$a_00_5 = {5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 ZwUnmapViewOfSection
		$a_00_6 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 } //1 VirtualProtectEx
		$a_00_7 = {2f 73 20 22 43 3a 5c 53 4d 47 43 61 74 63 68 65 72 2e 64 6c 6c 22 } //-100 /s "C:\SMGCatcher.dll"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*5+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*-100) >=7
 
}