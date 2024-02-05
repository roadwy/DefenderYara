
rule VirTool_Win32_DelfInject_gen_BE{
	meta:
		description = "VirTool:Win32/DelfInject.gen!BE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3c e8 0f 84 90 01 02 00 00 e8 90 01 02 ff ff 3c ff 0f 84 90 00 } //02 00 
		$a_03_1 = {8b 40 50 50 8b 45 90 01 01 e8 90 0a 1a 00 8b 90 01 01 3c 03 90 01 01 90 02 01 89 45 90 01 01 6a 04 68 00 30 00 00 8b 45 90 00 } //01 00 
		$a_03_2 = {25 ff 00 00 00 89 84 9d 90 01 02 ff ff 8b 84 b5 90 1b 00 ff ff 03 84 9d 90 1b 00 ff ff 25 ff 00 00 00 8a 84 85 90 1b 00 ff ff 8b 55 90 01 01 30 04 3a 47 ff 4d 90 01 01 75 90 00 } //02 00 
		$a_03_3 = {0f b7 78 06 4f 85 ff 72 90 01 01 47 33 db 8d 45 e8 50 8d 34 9b 8b 45 dc 8b 44 f0 10 50 8b 45 dc 8b 44 f0 14 03 45 fc 50 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}