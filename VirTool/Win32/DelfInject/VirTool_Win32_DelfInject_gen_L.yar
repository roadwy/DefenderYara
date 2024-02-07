
rule VirTool_Win32_DelfInject_gen_L{
	meta:
		description = "VirTool:Win32/DelfInject.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //0a 00  FindResourceA
		$a_00_1 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //0a 00  LoadResource
		$a_00_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 } //0a 00  CreateProcessA
		$a_01_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_02_4 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 90 01 01 8a 54 32 ff 80 e2 0f 32 c2 88 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 55 90 01 01 8a 54 1a ff 80 e2 f0 8a 4d 90 01 01 02 d1 88 54 18 ff 46 90 00 } //01 00 
		$a_02_5 = {8b f8 8b f2 4e 85 f6 7c 1b 46 33 db a1 90 01 04 e8 90 01 04 33 d2 8a 14 1f 33 c2 88 04 1f 43 4e 75 e8 90 00 } //01 00 
		$a_02_6 = {eb 09 49 c0 04 39 90 01 01 80 34 39 90 01 01 0b c9 75 f3 90 00 } //01 00 
		$a_02_7 = {8d 45 fc e8 90 01 04 8b 55 fc 0f b6 54 32 ff 33 d3 88 54 30 ff 43 46 4f 75 90 00 } //ff ff 
		$a_00_8 = {50 6c 65 61 73 65 20 76 69 73 69 74 20 77 77 77 2e 76 61 79 73 6f 66 74 2e 63 6f 6d 20 74 6f 20 67 65 74 20 6d 6f 72 65 20 64 65 74 61 69 6c } //00 00  Please visit www.vaysoft.com to get more detail
	condition:
		any of ($a_*)
 
}