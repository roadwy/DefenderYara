
rule VirTool_Win32_VBInject_gen_BT{
	meta:
		description = "VirTool:Win32/VBInject.gen!BT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 55 00 8b 42 0c 8b 72 14 8b 15 90 01 04 2b c6 8a 1c 02 03 d0 32 d9 88 1a 90 00 } //01 00 
		$a_03_1 = {66 8b c2 66 c1 f8 0f 66 8b d8 66 33 d9 66 89 0d 90 01 04 33 c6 66 3b d8 7f 1d 90 00 } //01 00 
		$a_03_2 = {68 f8 00 00 00 03 c8 51 8d 95 90 01 02 ff ff 52 e8 90 01 04 ff 15 90 01 04 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 81 bd 90 01 02 ff ff 50 45 00 00 74 14 90 00 } //01 00 
		$a_03_3 = {b9 01 00 00 00 33 c0 3b 45 90 01 01 7f 14 8b 15 90 01 04 8b 72 0c 2b 72 14 c6 04 06 cc 03 c1 eb e7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}