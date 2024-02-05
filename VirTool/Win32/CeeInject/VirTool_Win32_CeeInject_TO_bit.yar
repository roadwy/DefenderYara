
rule VirTool_Win32_CeeInject_TO_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TO!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 83 c4 08 8b d1 8a 12 80 f2 eb 88 10 ff 06 41 81 3e 90 01 02 00 00 75 90 00 } //01 00 
		$a_01_1 = {55 8b ec 51 81 c2 ba 0a 00 00 89 55 fc 8b 7d fc ff d7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TO_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TO!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 0c 28 f6 d1 30 0c 18 40 3b c6 72 f3 } //01 00 
		$a_03_1 = {8b ce 2b c8 51 03 c3 50 ff 93 90 01 04 01 44 24 90 01 01 59 59 39 74 24 90 01 01 72 90 00 } //01 00 
		$a_03_2 = {33 c0 81 34 83 90 01 04 40 83 f8 10 72 f3 90 00 } //01 00 
		$a_03_3 = {50 53 8b c6 e8 90 01 04 59 59 33 c9 8a 14 0b 8b 44 24 0c 30 14 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TO_bit_3{
	meta:
		description = "VirTool:Win32/CeeInject.TO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c3 bf 0a 00 00 00 99 f7 ff 80 c2 30 33 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 8b d8 49 85 db 75 db } //01 00 
		$a_03_1 = {8b d0 83 e2 0f 8a 92 90 01 04 33 db 8a d9 88 14 1e c1 e8 04 49 85 c0 75 e6 90 00 } //01 00 
		$a_03_2 = {30 1a eb 05 90 01 05 42 eb 05 90 01 05 49 eb 05 90 01 05 83 f9 00 eb 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TO_bit_4{
	meta:
		description = "VirTool:Win32/CeeInject.TO!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 1c 08 80 f3 90 01 01 f6 d3 80 f3 90 01 01 88 1c 08 90 00 } //01 00 
		$a_01_1 = {64 a1 30 00 00 00 8b 40 0c 8b 40 0c 8b 40 18 } //01 00 
		$a_03_2 = {73 24 0f b6 55 90 01 01 8b 45 90 01 01 8b 08 0f b6 41 90 01 01 8b 4d 90 01 01 0f b6 54 11 30 33 d0 0f b6 45 90 01 01 8b 4d 90 01 01 88 54 01 30 90 00 } //01 00 
		$a_03_3 = {52 8b 45 0c 50 8b 4d 08 51 8b 55 10 8b 42 34 50 8b 4d 90 01 01 51 6a 02 8b 55 90 01 01 8b 42 10 ff d0 b9 4d 5a 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_TO_bit_5{
	meta:
		description = "VirTool:Win32/CeeInject.TO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe c3 0f b6 f3 8a 14 3e 02 fa 0f b6 cf 8a 04 39 88 04 3e 88 14 39 0f b6 0c 3e 0f b6 c2 03 c8 0f b6 c1 8b 4c 24 90 01 01 8a 04 38 30 04 29 45 3b 6c 24 14 72 90 00 } //01 00 
		$a_03_1 = {0f b6 04 1f 33 c1 c1 e9 08 0f b6 c0 33 0c 85 90 01 04 47 3b fa 72 e8 90 00 } //01 00 
		$a_03_2 = {8b 0b 8b f1 8b 53 90 01 01 8d 5b 90 01 01 8b c1 c1 c6 0f c1 c0 0d 33 f0 c1 e9 0a 33 f1 8b c2 8b ca c1 c8 07 c1 c1 0e 33 c8 c1 ea 03 33 ca 03 f1 03 73 90 01 01 03 73 90 01 01 89 73 90 01 01 83 ed 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}