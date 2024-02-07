
rule VirTool_Win32_CeeInject_M{
	meta:
		description = "VirTool:Win32/CeeInject.M,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 00 65 00 2e 00 64 00 6c 00 6c 00 00 00 } //01 00 
		$a_01_1 = {6c 00 7a 00 2e 00 64 00 6c 00 6c 00 00 00 } //01 00 
		$a_03_2 = {45 78 65 63 75 74 65 46 69 6c 65 00 44 61 74 61 00 90 02 10 4c 7a 6d 61 55 6e 63 6f 6d 70 72 65 73 73 00 90 00 } //01 00 
		$a_01_3 = {2e 53 74 6f 6e 65 } //01 00  .Stone
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_M_2{
	meta:
		description = "VirTool:Win32/CeeInject.M,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 f4 8b 15 38 d7 41 00 8b 0d 3c d7 41 00 89 10 8b 15 40 d7 41 00 89 48 04 66 8b 0d 44 d7 41 00 89 50 08 8b 15 a4 63 42 00 52 66 89 48 0c 8d 84 24 20 03 00 00 68 48 d7 41 00 50 } //02 00 
		$a_01_1 = {00 00 6c 00 7a 00 2e 00 64 00 6c 00 6c 00 } //02 00 
		$a_01_2 = {00 00 6c 00 72 00 69 00 2e 00 64 00 6c 00 6c 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_M_3{
	meta:
		description = "VirTool:Win32/CeeInject.M,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 02 00 "
		
	strings :
		$a_03_0 = {6a 08 89 44 24 1d 89 44 24 21 89 44 24 25 66 89 44 24 29 88 44 24 2b 8d 44 24 1c 68 90 01 02 00 10 50 c6 44 24 24 00 e8 90 01 02 00 00 8b 4d 3c 8d 3c 29 83 c4 0c 81 3f 50 45 00 00 74 14 90 01 14 0f b7 47 14 66 85 c0 75 07 90 00 } //02 00 
		$a_01_1 = {6c 65 65 2e 64 6c 6c 00 44 61 74 61 00 45 78 65 63 75 74 65 46 69 6c 65 00 53 65 6c 66 } //03 00 
		$a_01_2 = {4e 65 77 20 45 58 45 20 69 6d 61 67 65 20 69 6e 6a 65 63 74 65 64 20 69 6e 74 6f 20 70 72 6f 63 65 73 73 2e } //01 00  New EXE image injected into process.
		$a_01_3 = {41 6c 6c 6f 63 61 74 65 64 20 4d 65 6d 20 66 6f 72 20 4e 65 77 20 45 58 45 20 61 74 20 25 58 2e 20 45 58 45 20 77 69 6c 6c 20 62 65 20 72 65 6c 6f 63 61 74 65 64 2e } //01 00  Allocated Mem for New EXE at %X. EXE will be relocated.
		$a_01_4 = {45 6e 63 6f 64 65 00 00 73 74 6f 6e 65 } //01 00 
		$a_01_5 = {45 6e 63 6f 64 65 00 00 2e 53 74 6f 6e 65 72 } //01 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_M_4{
	meta:
		description = "VirTool:Win32/CeeInject.M,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 41 00 56 00 5f 00 55 00 6e 00 70 00 61 00 63 00 6b 00 5f 00 64 00 6c 00 6c 00 5f 00 4d 00 75 00 74 00 65 00 78 00 } //01 00  AAV_Unpack_dll_Mutex
		$a_01_1 = {50 00 61 00 74 00 68 00 5b 00 20 00 43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 4c 00 52 00 49 00 5f 00 76 00 30 00 2e 00 30 00 2e 00 31 00 2e 00 39 00 5c 00 6c 00 72 00 69 00 2e 00 64 00 6c 00 6c 00 5d 00 } //01 00  Path[ C:\TEMP\LRI_v0.0.1.9\lri.dll]
		$a_01_2 = {46 00 61 00 69 00 6c 00 20 00 74 00 6f 00 20 00 67 00 65 00 6e 00 65 00 72 00 61 00 74 00 65 00 20 00 6c 00 72 00 69 00 2e 00 64 00 6c 00 6c 00 2e 00 } //01 00  Fail to generate lri.dll.
		$a_01_3 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6e 00 66 00 6f 00 7c 00 46 00 61 00 69 00 6c 00 20 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 41 00 41 00 56 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 43 00 6f 00 64 00 65 00 21 00 } //00 00  Productinfo|Fail Decrypt AAV protected Code!
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_M_5{
	meta:
		description = "VirTool:Win32/CeeInject.M,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 ec 14 02 00 00 a1 90 01 01 f0 00 10 33 c4 89 84 24 10 02 00 00 56 57 8b bc 24 20 02 00 00 68 90 01 01 c1 00 10 68 90 01 01 c1 00 10 e8 90 01 02 00 00 8b f0 83 c4 08 85 f6 0f 84 c6 00 00 00 90 00 } //01 00 
		$a_00_1 = {8b b4 24 9c 00 00 00 c1 ee 02 83 c3 5c 66 81 7d 00 4d 5a 89 74 24 10 74 14 68 c8 c1 00 10 e8 b2 fc ff ff 83 c4 04 33 c0 e9 33 01 00 00 8b 45 3c 03 c5 81 38 50 45 00 00 74 14 68 b4 c1 00 10 e8 91 fc ff ff } //02 00 
		$a_01_2 = {2e 73 6d 69 6c 65 79 } //02 00  .smiley
		$a_01_3 = {54 68 69 73 20 44 6c 6c 20 61 6c 67 6f 72 69 74 68 6d 20 69 73 6e 27 74 20 73 61 6d 65 20 2e } //02 00  This Dll algorithm isn't same .
		$a_01_4 = {43 3a 5c 4c 52 49 4c 6f 67 2e 74 78 74 } //02 00  C:\LRILog.txt
		$a_01_5 = {54 68 69 73 20 44 6c 6c 20 68 61 76 65 20 6e 6f 74 20 65 6e 63 72 79 70 74 65 64 2e 20 49 74 20 72 75 6e 73 20 69 6e 20 6e 6f 6e 2d 70 72 6f 74 65 63 74 69 6f 6e 20 6d 6f 64 65 2e } //02 00  This Dll have not encrypted. It runs in non-protection mode.
		$a_01_6 = {4c 52 49 2e 64 6c 6c } //01 00  LRI.dll
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_M_6{
	meta:
		description = "VirTool:Win32/CeeInject.M,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 f4 8b 15 58 e7 00 10 8b 0d 5c e7 00 10 89 10 8b 15 60 e7 00 10 89 48 04 8b 0d 64 e7 00 10 89 50 08 66 8b 15 68 e7 00 10 89 48 0c 66 89 50 10 8d 44 24 08 50 ff 15 04 c0 00 10 8b f0 68 6c e7 00 10 56 } //01 00 
		$a_01_1 = {75 f4 8b 0d bc d7 00 10 8b 15 c0 d7 00 10 89 08 8b 0d c4 d7 00 10 89 50 04 8b 15 c8 d7 00 10 89 48 08 66 8b 0d cc d7 00 10 89 50 0c 56 8d 54 24 04 52 66 89 48 10 ff 15 4c c0 00 10 8b f0 68 d0 d7 00 10 56 } //01 00 
		$a_03_2 = {6a 08 89 44 24 1d 89 44 24 21 89 44 24 25 66 89 44 24 29 88 44 24 2b 8d 44 24 1c 68 90 01 02 00 10 50 c6 44 24 24 00 e8 90 01 02 00 00 8b 4d 3c 8d 3c 29 83 c4 0c 81 3f 50 45 00 00 74 14 90 01 14 0f b7 47 14 66 85 c0 75 07 90 00 } //03 00 
		$a_01_3 = {5c 00 4c 00 52 00 49 00 2e 00 64 00 6c 00 6c 00 } //03 00  \LRI.dll
		$a_01_4 = {4e 65 77 20 45 58 45 20 69 6d 61 67 65 20 69 6e 6a 65 63 74 65 64 20 69 6e 74 6f 20 70 72 6f 63 65 73 73 2e } //03 00  New EXE image injected into process.
		$a_01_5 = {52 79 61 6e 20 50 72 6f 6a 65 63 74 5c 41 6e 74 69 2d 41 6e 74 69 56 69 72 75 73 } //01 00  Ryan Project\Anti-AntiVirus
		$a_01_6 = {41 6c 6c 6f 63 61 74 65 64 20 4d 65 6d 20 66 6f 72 20 4e 65 77 20 45 58 45 20 61 74 20 25 58 2e 20 45 58 45 20 77 69 6c 6c 20 62 65 20 72 65 6c 6f 63 61 74 65 64 2e } //01 00  Allocated Mem for New EXE at %X. EXE will be relocated.
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_M_7{
	meta:
		description = "VirTool:Win32/CeeInject.M,SIGNATURE_TYPE_PEHSTR,63 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 41 6e 74 69 41 6e 74 69 56 69 72 75 73 5f 63 6f 6d 6d 61 6e 64 } //01 00  \AntiAntiVirus_command
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64 } //01 00  WriteProcessMemory failed
		$a_01_2 = {4e 65 77 20 45 58 45 20 69 6d 61 67 65 20 69 6e 6a 65 63 74 65 64 20 69 6e 74 6f 20 70 72 6f 63 65 73 73 2e } //00 00  New EXE image injected into process.
	condition:
		any of ($a_*)
 
}