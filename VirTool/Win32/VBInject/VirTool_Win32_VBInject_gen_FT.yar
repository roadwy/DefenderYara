
rule VirTool_Win32_VBInject_gen_FT{
	meta:
		description = "VirTool:Win32/VBInject.gen!FT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 95 e3 35 69 } //01 00 
		$a_01_1 = {68 d0 37 10 f2 } //01 00 
		$a_01_2 = {66 b9 c3 00 e8 } //01 00 
		$a_01_3 = {c7 04 81 07 00 01 00 } //01 00 
		$a_01_4 = {b8 75 bb db fb f7 d8 b9 3e 37 f2 3c 83 d1 00 f7 d9 } //01 00 
		$a_03_5 = {66 33 0c 42 e8 90 01 04 8a d8 90 00 } //01 00 
		$a_00_6 = {c8 63 db 63 c8 63 91 63 d7 63 c8 63 d1 63 d7 63 d2 63 c5 } //01 00 
		$a_03_7 = {8b 91 a4 00 00 00 8b 85 90 01 02 ff ff 83 c2 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}