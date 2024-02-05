
rule VirTool_Win32_CeeInject_BDB_bit{
	meta:
		description = "VirTool:Win32/CeeInject.BDB!bit,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 08 8b c1 c1 e0 04 89 04 24 8b 44 24 0c 01 04 24 8b d1 c1 ea 05 89 54 24 08 8b 44 24 14 01 44 24 08 8b 44 24 10 03 c1 33 44 24 08 33 04 24 } //01 00 
		$a_01_1 = {8b d6 c1 e2 04 89 54 24 30 8b 44 24 20 01 44 24 30 89 74 24 34 c1 6c 24 34 05 8b 44 24 24 01 44 24 34 8d 04 37 33 44 24 34 b9 f7 ff ff ff 33 44 24 30 2b 4c 24 28 43 2b e8 03 f9 83 fb 20 } //01 00 
		$a_01_2 = {8b d6 c1 e2 04 89 54 24 10 8b 44 24 1c 01 44 24 10 89 74 24 38 c1 6c 24 38 05 8b 44 24 20 01 44 24 38 8d 04 37 33 44 24 38 b9 f7 ff ff ff 33 44 24 10 2b 4c 24 24 43 2b e8 03 f9 83 fb 20 } //01 00 
		$a_01_3 = {8b c6 c1 e0 04 89 44 24 10 8b 44 24 1c 01 44 24 10 89 74 24 38 c1 6c 24 38 05 8b 44 24 20 01 44 24 38 8d 0c 37 33 4c 24 38 ba f7 ff ff ff 33 4c 24 10 2b 54 24 24 43 2b e9 03 fa 83 fb 20 } //00 00 
	condition:
		any of ($a_*)
 
}