
rule VirTool_Win32_CeeInject_AO{
	meta:
		description = "VirTool:Win32/CeeInject.AO,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 31 04 83 c0 ?? 88 44 17 fb 83 c1 05 3b 8d 9c fd ff ff 76 b6 } //1
		$a_03_1 = {52 6a 24 52 52 52 50 52 ff 15 ?? ?? ?? ?? 8b 45 cc ff 74 38 34 ff 35 ?? ?? ?? ?? ff 15 } //1
		$a_01_2 = {f7 84 d1 1c 01 00 00 00 00 00 80 0f 44 f0 f7 84 d1 1c 01 00 00 00 00 00 20 89 75 c8 8b 75 d0 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}