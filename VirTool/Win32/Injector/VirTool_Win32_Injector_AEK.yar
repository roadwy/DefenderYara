
rule VirTool_Win32_Injector_AEK{
	meta:
		description = "VirTool:Win32/Injector.AEK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {f7 d0 40 40 8b c8 33 c0 41 66 ad 66 2b c2 74 04 2b f1 eb f5 } //01 00 
		$a_01_1 = {8b 07 8b 16 33 d0 46 88 17 8b c3 48 74 0a 47 8b d8 e2 ed } //01 00 
		$a_01_2 = {8b 45 f8 ff 45 f8 47 47 40 47 47 8b 4d f4 3b c1 72 } //01 00 
		$a_01_3 = {0f b7 00 8b 4e 1b 4e 4e 4e 8d 04 81 8b 4d fc 03 c1 8b 00 03 c1 eb d1 } //01 00 
		$a_01_4 = {40 48 74 12 47 47 8b 45 f8 ff 45 f8 47 8b 4d f4 47 40 3b c1 72 c5 } //00 00 
		$a_00_5 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}