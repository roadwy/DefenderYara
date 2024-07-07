
rule VirTool_Win32_DelfInject_gen_S{
	meta:
		description = "VirTool:Win32/DelfInject.gen!S,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 09 00 00 "
		
	strings :
		$a_01_0 = {52 74 6c 44 65 63 6f 6d 70 72 65 73 73 42 75 66 66 65 72 } //1 RtlDecompressBuffer
		$a_01_1 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 } //1 SizeofResource
		$a_01_2 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //1 LockResource
		$a_00_3 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_01_4 = {46 72 65 65 52 65 73 6f 75 72 63 65 } //1 FreeResource
		$a_00_5 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1 FindResourceA
		$a_00_6 = {5c 5c 2e 5c 4e 54 49 43 45 } //4 \\.\NTICE
		$a_00_7 = {44 41 45 4d 4f 4e } //2 DAEMON
		$a_01_8 = {8d 44 30 ff 50 8b 45 fc 8a 44 30 ff 25 ff 00 00 00 33 d2 52 50 8b c3 99 03 45 e0 13 55 e4 33 04 24 33 54 24 04 83 c4 08 5a 88 02 43 46 4f 75 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*4+(#a_00_7  & 1)*2+(#a_01_8  & 1)*10) >=16
 
}