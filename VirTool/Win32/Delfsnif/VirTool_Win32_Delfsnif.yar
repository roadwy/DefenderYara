
rule VirTool_Win32_Delfsnif{
	meta:
		description = "VirTool:Win32/Delfsnif,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_00_0 = {33 db 8a 98 00 01 00 00 02 14 18 81 e2 ff 00 00 00 8a 14 10 32 16 88 11 41 46 ff 4d fc 75 a5 } //2
		$a_02_1 = {8b 16 88 c3 32 da c1 e8 08 33 04 9d 90 01 04 88 c3 32 de c1 e8 08 33 04 9d 90 00 } //2
		$a_02_2 = {89 f9 83 e1 03 e3 11 88 c3 32 1e c1 e8 08 46 33 04 9d 90 01 04 e2 ef 35 ff ff ff ff 90 00 } //2
		$a_00_3 = {50 6f 72 74 69 6f 6e 73 20 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 39 2c 32 30 30 33 20 41 76 65 6e 67 65 72 20 62 79 20 4e 68 54 } //4 Portions Copyright (c) 1999,2003 Avenger by NhT
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //5 WriteProcessMemory
		$a_00_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //4 VirtualAllocEx
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_00_3  & 1)*4+(#a_01_4  & 1)*5+(#a_00_5  & 1)*4) >=15
 
}