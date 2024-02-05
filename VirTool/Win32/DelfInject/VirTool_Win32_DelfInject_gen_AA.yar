
rule VirTool_Win32_DelfInject_gen_AA{
	meta:
		description = "VirTool:Win32/DelfInject.gen!AA,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 08 81 f9 ff 00 00 00 75 07 b9 01 00 00 00 eb 01 41 40 90 01 01 75 ea } //01 00 
		$a_01_1 = {30 10 81 fa ff 00 00 00 75 07 ba 01 00 00 00 eb 01 42 40 90 01 01 75 ea } //01 00 
		$a_01_2 = {30 18 81 fb ff 00 00 00 75 07 bb 01 00 00 00 eb 01 43 40 90 01 01 75 ea } //02 00 
		$a_01_3 = {0f 01 4d fa 8a 45 ff 2c e8 74 04 2c 17 75 06 c6 45 f9 01 eb 04 c6 45 f9 00 8a 45 f9 } //01 00 
		$a_03_4 = {6a 40 68 00 30 00 00 8b 45 90 01 01 50 8b 45 90 01 01 8b 40 34 50 8b 90 03 06 04 85 90 01 02 ff ff 45 90 01 01 50 90 03 01 01 ff e8 90 00 } //05 00 
		$a_03_5 = {8d 45 f8 8a 13 80 f2 90 01 01 90 02 03 81 e2 ff 00 00 00 33 d6 e8 90 01 04 8b 55 f8 8b 45 fc e8 90 01 04 8b 45 fc 81 fe ff 00 00 00 75 07 be 01 00 00 00 eb 01 46 43 4f 75 90 00 } //05 00 
		$a_03_6 = {8d 45 f4 8b 55 fc 8b 4d f8 0f b6 54 0a ff 33 d3 e8 90 01 04 8b 55 f4 8b c7 e8 90 00 } //05 00 
		$a_03_7 = {8d 45 ec 8b 55 fc 8b 4d f4 0f b6 54 0a ff 33 d3 e8 90 01 04 8b 55 ec 8b 45 f8 e8 90 00 } //05 00 
		$a_01_8 = {8b 55 f4 8b 4d fc 8b 5d f4 0f b6 4c 19 ff 33 4d f0 88 4c 10 ff ff 45 f0 ff 45 f4 ff 4d ec 75 } //05 00 
		$a_03_9 = {8b 55 f0 8b 4d fc 8b 5d f0 0f b6 4c 19 ff 33 4d ec 88 4c 10 ff 90 02 04 ff 45 ec ff 45 f0 ff 4d e8 75 90 00 } //05 00 
		$a_01_10 = {8b 45 f8 8b 55 f0 8a 04 10 33 d2 8a 55 ef 8b 4d fc 32 04 11 8b 55 f4 8b 4d f0 88 04 0a } //00 00 
	condition:
		any of ($a_*)
 
}