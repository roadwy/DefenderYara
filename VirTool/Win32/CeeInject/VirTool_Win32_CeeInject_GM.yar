
rule VirTool_Win32_CeeInject_GM{
	meta:
		description = "VirTool:Win32/CeeInject.GM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 03 00 0f b6 44 24 f1 3c ff 75 02 eb 1b c1 e0 15 74 fb c1 e3 02 ff e1 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_CeeInject_GM_2{
	meta:
		description = "VirTool:Win32/CeeInject.GM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {d9 c1 d8 e1 d8 e1 d8 c1 d8 c1 d8 c1 dd da d9 c1 dc 1d 00 46 40 00 df e0 9e 76 e5 } //01 00 
		$a_03_1 = {8b c7 6a 21 99 59 f7 f9 dd 04 c5 90 01 02 40 00 8d b4 05 34 f0 ff ff e8 f3 0d 00 00 dd 05 90 01 02 40 00 8a d8 e8 e6 0d 00 00 32 d8 88 1e 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}