
rule VirTool_Win32_Injector_CL{
	meta:
		description = "VirTool:Win32/Injector.CL,SIGNATURE_TYPE_PEHSTR_EXT,19 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 fb 2e 0f 85 90 01 04 ff 44 24 0c 8b 6c 24 0c 0f b6 5d 00 83 fb 64 74 0f 8b 6c 24 0c 0f b6 5d 00 83 fb 65 74 02 eb 07 b8 01 00 00 00 eb 02 90 00 } //01 00 
		$a_03_1 = {c7 84 24 88 04 00 00 40 00 00 00 c7 84 24 8c 04 00 00 00 30 00 00 90 02 40 68 90 01 01 00 00 00 90 00 } //0a 00 
		$a_03_2 = {54 d1 40 00 00 00 00 70 00 f0 40 90 09 05 00 00 00 00 00 00 90 00 } //01 00 
		$a_03_3 = {8b 45 28 89 84 24 90 01 04 8b 5d 34 03 9c 24 90 01 04 53 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Injector_CL_2{
	meta:
		description = "VirTool:Win32/Injector.CL,SIGNATURE_TYPE_PEHSTR_EXT,64 00 15 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 44 24 68 58 59 59 59 90 02 04 04 00 00 00 90 00 } //01 00 
		$a_01_1 = {8b 2c 24 c7 45 0c 00 30 00 00 c7 45 10 40 00 00 00 } //01 00 
		$a_03_2 = {54 d1 40 00 00 00 00 70 00 f0 40 90 09 05 00 00 00 00 00 00 90 00 } //0a 00 
		$a_01_3 = {83 fb 5a 7f 07 b8 01 00 00 00 eb 02 31 c0 21 c0 74 15 8b 6c 24 14 0f b7 5d 00 83 cb 20 53 8b 6c 24 18 58 66 89 45 00 } //0a 00 
		$a_03_4 = {83 fb 2e 0f 85 90 01 04 ff 44 24 0c 8b 6c 24 0c 0f b6 5d 00 83 fb 64 74 0f 8b 6c 24 0c 0f b6 5d 00 83 fb 65 74 02 eb 07 b8 01 00 00 00 eb 02 90 00 } //00 00 
		$a_00_5 = {80 10 00 00 d5 2f 2f 04 71 8f a2 76 31 e6 f1 6e 00 10 00 80 } //80 10 
	condition:
		any of ($a_*)
 
}