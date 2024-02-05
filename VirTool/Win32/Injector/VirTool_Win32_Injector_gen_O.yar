
rule VirTool_Win32_Injector_gen_O{
	meta:
		description = "VirTool:Win32/Injector.gen!O,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64 } //01 00 
		$a_00_1 = {68 74 6d 6c 66 69 6c 65 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00 
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00 
		$a_00_3 = {33 c0 8a 0c 03 80 f1 88 } //01 00 
		$a_00_4 = {a7 e1 ea e1 e6 a7 fc e3 fb ed fa fe a6 ec e4 e4 } //01 00 
		$a_02_5 = {85 c0 74 0e 6a 00 50 68 90 01 04 ff 15 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}