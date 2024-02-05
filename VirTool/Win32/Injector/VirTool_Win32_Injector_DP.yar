
rule VirTool_Win32_Injector_DP{
	meta:
		description = "VirTool:Win32/Injector.DP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b d8 85 db 7e 31 be 01 00 00 00 8b 45 fc 8a 44 30 ff 8b 55 f4 8a 54 32 ff 32 c2 88 45 f3 8d 45 ec 8a 55 f3 e8 } //01 00 
		$a_01_1 = {25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 e8 fb ff ff 8b 55 e8 30 04 3a 47 4b 0f 85 } //01 00 
		$a_01_2 = {89 45 f8 8b de 66 81 3b 4d 5a 0f 85 d2 01 00 00 8b c6 33 d2 52 50 8b 43 3c } //01 00 
		$a_03_3 = {8b 47 28 03 45 f0 89 85 7c ff ff ff 8d 85 cc fe ff ff 50 8b 45 e0 50 e8 90 01 04 8b 45 e0 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}