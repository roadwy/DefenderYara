
rule VirTool_Win32_VBInject_gen_CC{
	meta:
		description = "VirTool:Win32/VBInject.gen!CC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6c 68 fe 6c 5c fe aa 71 94 fd } //01 00 
		$a_00_1 = {f4 59 fc 0d f5 04 00 00 00 04 58 ff fc a0 f4 50 fc 0d f5 05 00 00 00 } //01 00 
		$a_01_2 = {f5 fe 00 00 00 c2 04 58 ff 9d 44 2c ff fb 94 1c ff fc 22 04 58 ff 9d fb 12 } //01 00 
		$a_01_3 = {6d 4d 41 69 6e 00 } //01 00  䵭楁n
	condition:
		any of ($a_*)
 
}