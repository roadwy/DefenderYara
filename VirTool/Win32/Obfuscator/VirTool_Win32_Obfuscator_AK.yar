
rule VirTool_Win32_Obfuscator_AK{
	meta:
		description = "VirTool:Win32/Obfuscator.AK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {ac 3c 2e 75 fb 89 f1 29 f9 8d 04 8d 00 00 00 00 29 c4 89 fe 89 e7 50 57 f3 a4 c7 07 44 4c 4c 00 ff 55 f8 } //01 00 
		$a_03_1 = {ff 36 ff 93 90 01 02 00 00 89 c7 83 c6 04 8b 0e 83 c6 04 8b 06 09 c0 74 09 50 57 e8 90 01 02 ff ff 89 06 83 c6 04 e2 ec eb d2 61 90 00 } //01 00 
		$a_02_2 = {8b 7d 08 0f b6 1f 09 db 74 0c f7 e3 d1 e0 35 90 01 04 47 eb ed 89 45 fc 61 8b 45 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}