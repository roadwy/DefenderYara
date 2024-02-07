
rule VirTool_Win32_VBInject_AFC{
	meta:
		description = "VirTool:Win32/VBInject.AFC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 04 00 00 00 c7 45 90 f8 fc 0c 00 c7 45 94 01 00 00 00 83 65 d4 00 eb 0f 8b 45 d4 03 45 94 0f 80 15 3d 00 00 89 45 d4 8b 45 d4 3b 45 90 7f 69 } //01 00 
		$a_03_1 = {2b 78 14 c7 04 fb 5a 7e 7d 74 c7 44 fb 04 4e 81 83 1f 8b 58 0c bf 90 01 04 2b 78 14 c7 04 fb 2e 62 7d 6c c7 44 fb 04 2a 14 f4 43 90 00 } //00 00 
		$a_00_2 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}