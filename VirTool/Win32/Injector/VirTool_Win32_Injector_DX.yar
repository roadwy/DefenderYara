
rule VirTool_Win32_Injector_DX{
	meta:
		description = "VirTool:Win32/Injector.DX,SIGNATURE_TYPE_PEHSTR_EXT,64 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {7e 2d 8b 4c 24 04 80 3c 08 64 75 1a 80 7c 08 01 7d 75 13 80 7c 08 02 77 75 0c 80 7c 08 06 61 75 05 05 e4 03 00 00 80 34 08 bb 40 3b c2 7c d7 } //2
		$a_01_1 = {0f 84 dd 01 00 00 8b 55 54 8b 44 24 14 6a 00 52 53 56 50 ff 15 } //1
		$a_01_2 = {8b 4c 24 38 8b 54 24 14 51 52 ff d0 85 c0 74 2a 53 e8 } //1
		$a_01_3 = {d5 cf df d7 d7 95 df d7 d7 } //1
		$a_01_4 = {f5 cf ee d5 d6 da cb ed d2 de cc f4 dd e8 de d8 cf d2 d4 d5 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}