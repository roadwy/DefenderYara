
rule VirTool_Win32_CeeInject_gen_JY{
	meta:
		description = "VirTool:Win32/CeeInject.gen!JY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {99 b9 32 00 00 00 f7 f9 83 c2 32 } //01 00 
		$a_01_1 = {8b 51 3c 8b 45 f8 6b c0 28 03 45 08 8d 8c 10 f8 00 00 00 } //01 00 
		$a_01_2 = {8b 48 3c 8b 55 f8 6b d2 28 03 55 08 8d 84 0a f8 00 00 00 } //01 00 
		$a_03_3 = {0f be 11 0f be 85 90 01 02 ff ff 33 d0 8b 4d 90 01 01 03 8d 90 01 02 ff ff 88 11 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}