
rule VirTool_Win32_CryptInject_MTB{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 0f 7e 14 08 90 0a ff 00 66 0f 6e d3 90 0a 50 00 5b 90 0a 50 00 ff 34 08 90 00 } //01 00 
		$a_02_1 = {66 0f 7e 14 08 90 02 70 83 e9 fc 90 02 50 81 f9 90 01 02 00 00 0f 85 90 01 02 ff ff 90 02 ff 66 0f ef d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CryptInject_MTB_2{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_02_1 = {83 c1 04 0f 8d 90 01 02 ff ff 90 0a ff 00 ff 34 0f 90 02 30 5b 90 02 30 31 f3 90 02 30 89 1c 0a 90 02 40 83 e9 08 90 02 30 83 c1 04 0f 8d 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CryptInject_MTB_3{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_02_1 = {83 ff 00 0f 8d 90 01 02 ff ff 90 0a 50 00 29 df 90 0a 50 00 8f 04 38 90 0a 50 00 ff 75 34 90 0a 50 00 31 75 34 90 0a 50 00 8f 45 34 90 0a 50 00 ff 34 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CryptInject_MTB_4{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 8b 45 08 e8 90 01 04 ff 45 f8 81 7d f8 90 01 04 75 e7 90 00 } //01 00 
		$a_02_1 = {88 4d f7 89 55 f8 89 45 fc 8b 45 fc 03 45 f8 73 05 e8 90 01 04 89 45 90 01 01 8b 45 90 01 01 8a 00 88 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8a 45 90 01 01 30 45 f7 8b 45 90 01 01 8a 55 f7 88 10 8b e5 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CryptInject_MTB_5{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_02_1 = {66 0f 6e c6 90 02 10 66 0f 6e c9 90 02 10 c5 f0 57 c8 90 02 10 66 0f 7e c9 90 02 10 39 c1 90 13 0f 77 90 02 10 46 90 02 10 ff 37 90 02 10 59 90 00 } //01 00 
		$a_02_2 = {66 0f 6e c6 90 02 10 66 0f 6e c9 90 02 10 66 0f ef c8 90 02 10 66 0f 7e c9 90 02 10 39 c1 90 13 0f 77 90 02 10 46 90 02 10 ff 37 90 02 10 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}