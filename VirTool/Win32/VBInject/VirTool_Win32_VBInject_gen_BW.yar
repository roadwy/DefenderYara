
rule VirTool_Win32_VBInject_gen_BW{
	meta:
		description = "VirTool:Win32/VBInject.gen!BW,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {6c 78 fe 6c 6c fe aa 71 a4 fd } //01 00 
		$a_01_1 = {fb 11 6c 78 ff 04 4c ff fc a0 04 78 ff 66 10 ff 8c 00 f5 08 00 00 00 } //01 00 
		$a_03_2 = {f4 58 fc 0d f5 00 00 00 00 04 90 01 01 ff fc a0 90 02 02 f4 59 fc 0d f5 01 00 00 00 04 90 01 01 ff fc a0 90 02 02 f4 59 fc 0d f5 02 90 00 } //01 00 
		$a_01_3 = {6b 6e ff 6b 6c ff fb 12 e7 04 44 ff } //01 00 
		$a_03_4 = {f3 c3 00 fc 0d 90 02 09 f3 cc 00 fc 0d 90 00 } //01 00 
		$a_03_5 = {f5 58 59 59 59 59 90 02 30 f3 59 50 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}