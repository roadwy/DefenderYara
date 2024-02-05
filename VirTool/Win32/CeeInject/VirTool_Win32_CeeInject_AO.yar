
rule VirTool_Win32_CeeInject_AO{
	meta:
		description = "VirTool:Win32/CeeInject.AO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 44 31 04 83 c0 90 01 01 88 44 17 fb 83 c1 05 3b 8d 9c fd ff ff 76 b6 90 00 } //01 00 
		$a_03_1 = {52 6a 24 52 52 52 50 52 ff 15 90 01 04 8b 45 cc ff 74 38 34 ff 35 90 01 04 ff 15 90 00 } //01 00 
		$a_01_2 = {f7 84 d1 1c 01 00 00 00 00 00 80 0f 44 f0 f7 84 d1 1c 01 00 00 00 00 00 20 89 75 c8 8b 75 d0 74 } //00 00 
	condition:
		any of ($a_*)
 
}