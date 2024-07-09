
rule VirTool_Win32_CryptInject_MTB{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 0f 7e 14 08 90 0a ff 00 66 0f 6e d3 90 0a 50 00 5b 90 0a 50 00 ff 34 08 } //1
		$a_02_1 = {66 0f 7e 14 08 [0-70] 83 e9 fc [0-50] 81 f9 ?? ?? 00 00 0f 85 ?? ?? ff ff [0-ff] 66 0f ef d1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CryptInject_MTB_2{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_02_1 = {83 c1 04 0f 8d ?? ?? ff ff 90 0a ff 00 ff 34 0f [0-30] 5b [0-30] 31 f3 [0-30] 89 1c 0a [0-40] 83 e9 08 [0-30] 83 c1 04 0f 8d ?? ?? ff ff } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CryptInject_MTB_3{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_02_1 = {83 ff 00 0f 8d ?? ?? ff ff 90 0a 50 00 29 df 90 0a 50 00 8f 04 38 90 0a 50 00 ff 75 34 90 0a 50 00 31 75 34 90 0a 50 00 8f 45 34 90 0a 50 00 ff 34 3a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CryptInject_MTB_4{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 55 f8 8b 45 08 e8 ?? ?? ?? ?? ff 45 f8 81 7d f8 ?? ?? ?? ?? 75 e7 } //1
		$a_02_1 = {88 4d f7 89 55 f8 89 45 fc 8b 45 fc 03 45 f8 73 05 e8 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 8a 00 88 45 ?? 8b 45 ?? 89 45 ?? 8a 45 ?? 30 45 f7 8b 45 ?? 8a 55 f7 88 10 8b e5 5d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule VirTool_Win32_CryptInject_MTB_5{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
		$a_02_1 = {66 0f 6e c6 [0-10] 66 0f 6e c9 [0-10] c5 f0 57 c8 [0-10] 66 0f 7e c9 [0-10] 39 c1 90 13 0f 77 [0-10] 46 [0-10] ff 37 [0-10] 59 } //1
		$a_02_2 = {66 0f 6e c6 [0-10] 66 0f 6e c9 [0-10] 66 0f ef c8 [0-10] 66 0f 7e c9 [0-10] 39 c1 90 13 0f 77 [0-10] 46 [0-10] ff 37 [0-10] 59 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}