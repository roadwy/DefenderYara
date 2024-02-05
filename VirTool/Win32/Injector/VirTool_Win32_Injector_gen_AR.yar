
rule VirTool_Win32_Injector_gen_AR{
	meta:
		description = "VirTool:Win32/Injector.gen!AR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {7f 22 8b 45 fc 99 f7 3d 90 01 04 8b 45 08 03 45 fc 8a 08 32 8a 90 01 04 8b 55 08 03 55 fc 88 0a eb cd 90 00 } //01 00 
		$a_01_1 = {77 69 6e 00 73 79 73 00 61 70 70 00 6d 65 00 } //01 00 
		$a_01_2 = {2d 57 43 52 54 2d 0d 0a 0d 0a f6 45 e8 01 74 06 0f b7 45 ec eb 03 } //01 00 
		$a_03_3 = {79 08 49 81 c9 00 ff ff ff 41 8b 45 08 03 45 90 01 01 8a 10 32 94 8d 90 01 04 8b 45 08 03 45 90 01 01 88 10 e9 90 00 } //01 00 
		$a_03_4 = {6a 40 68 00 30 00 00 8b 90 01 05 8b 90 01 01 50 90 01 01 8b 90 01 01 90 1b 01 8b 90 01 01 34 90 00 } //01 00 
		$a_03_5 = {66 8b 51 06 39 95 90 01 02 ff ff 7d 90 01 01 8b 85 90 01 02 ff ff 8b 48 3c 8b 95 90 1b 00 ff ff 6b d2 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}